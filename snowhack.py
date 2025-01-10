import streamlit as st
import snowflake.connector
import os
from hashlib import sha256
import io
from pypdf import PdfReader
import ftfy
import nltk
from snowflake.core import Root

CORTEX_SEARCH_DATABASE = "SAMPLEDATA"
CORTEX_SEARCH_SCHEMA = "PUBLIC"
CORTEX_SEARCH_SERVICE = "docs_search_svc"

def init_snowflake_connection():
    """Initialize Snowflake connection"""
    return snowflake.connector.connect(
        user='SNOWHACK10',
        password='Snowhack10',
        account='nrdbnwt-qob04556',
        warehouse='COMPUTE_WH',
        database='SAMPLEDATA',
        schema='PUBLIC'
    )

def authenticate(conn, username, password):
    """Authenticate user against Snowflake database"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT USER_ID FROM USERS 
        WHERE USERNAME = %s AND PASSWORD = %s
        """, (username, sha256(password.encode()).hexdigest()))
        result = cursor.fetchone()
        return bool(result)
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return False
    finally:
        cursor.close()

def register_user(conn, username, password):
    """Register new user in Snowflake database"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO USERS (USERNAME, PASSWORD)
        VALUES (%s, %s)
        """, (username, sha256(password.encode()).hexdigest()))
        return True
    except Exception as e:
        st.error(f"Registration error: {str(e)}")
        return False
    finally:
        cursor.close()

def extract_text_from_pdf(file_content):
    """Extract text content from PDF file"""
    try:
        pdf_file = io.BytesIO(file_content)
        pdf_reader = PdfReader(pdf_file)
        text_content = ""

        for page in pdf_reader.pages:
            text_content += page.extract_text() + "\n\n"

        return text_content
    except Exception as e:
        st.error(f"Error extracting PDF content: {str(e)}")
        return None

def clean_text(text):
    """Clean text using ftfy library and additional cleaning"""
    text = ftfy.fix_text(text)
    text = text.strip()
    return text

def process_and_upload_file(conn, file, stage_name="DOCS"):
    """Process a file, upload to stage, and store chunks"""
    cursor = None
    temp_dir = "/tmp/uploads"
    local_file_path = None

    try:
        # Check if file already exists in session
        if check_file_exists(conn, file.name, st.session_state.username, st.session_state.session_id):
            st.warning(f"File {file.name} already processed in this session. Skipping...")
            return True

        os.makedirs(temp_dir, mode=0o777, exist_ok=True)

        cursor = conn.cursor()
        file_content = file.getvalue()

        # Extract text and clean it
        if file.name.lower().endswith('.pdf'):
            text_content = extract_text_from_pdf(file_content)
            if text_content is None:
                return False
        else:
            text_content = file_content.decode('utf-8', errors='ignore')

        # Clean the extracted text
        text_content = clean_text(text_content)

        # Save file locally for stage upload
        safe_filename = file.name.replace(" ", "_")
        local_file_path = os.path.join(temp_dir, safe_filename)

        with open(local_file_path, "wb") as f:
            f.write(file_content)

        # Upload to stage
        put_command = f"PUT 'file://{local_file_path}' @{stage_name} AUTO_COMPRESS=FALSE OVERWRITE=TRUE"
        cursor.execute(put_command)
        st.success(f"✅ {file.name} uploaded to stage")

        # Store metadata
        cursor.execute("""
        INSERT INTO UPLOADED_FILES_METADATA 
        (USERNAME, SESSION_ID, STAGE_NAME, FILE_NAME)
        VALUES (%s, %s, %s, %s)
        """, (
            st.session_state.username,
            st.session_state.session_id,
            stage_name,
            file.name
        ))

        return True

    except Exception as e:
        st.error(f"Error processing {file.name}: {str(e)}")
        return False
    finally:
        if cursor:
            cursor.close()
        try:
            if local_file_path and os.path.exists(local_file_path):
                os.remove(local_file_path)
        except Exception:
            pass

def check_file_exists(conn, filename, username, session_id):
    """Check if file already exists in the current session"""
    try:
        cursor = conn.cursor()
        cursor.execute("""
        SELECT COUNT(*) 
        FROM UPLOADED_FILES_METADATA 
        WHERE USERNAME = %s 
        AND SESSION_ID = %s 
        AND FILE_NAME = %s
        """, (username, session_id, filename))
        count = cursor.fetchone()[0]
        return count > 0
    except Exception as e:
        st.error(f"Error checking file existence: {str(e)}")
        return False
    finally:
        cursor.close()

def get_similar_chunks_search_service(query):
    """Search relevant chunks using the Cortex Search Service"""
    root = Root(st.session_state.snowflake_connection)
    svc = root.databases[CORTEX_SEARCH_DATABASE].schemas[CORTEX_SEARCH_SCHEMA].cortex_search_services[CORTEX_SEARCH_SERVICE]

    filter_obj = {"@eq": {"username": st.session_state["username"], "session_id": st.session_state["session_id"]}}
    response = svc.search(query, ["chunk", "relative_path", "size"], filter=filter_obj, limit=3)

    st.sidebar.json(response.to_json())
    return response.to_json()

def main():
    st.set_page_config(page_title="Document Search System", layout="wide")

    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False

    # Initialize Snowflake connection
    if 'snowflake_connection' not in st.session_state:
        st.session_state.snowflake_connection = init_snowflake_connection()

    conn = st.session_state.snowflake_connection
    if not conn:
        st.error("Failed to connect to Snowflake")
        return

    # Authentication UI
    if not st.session_state.authenticated:
        tab1, tab2 = st.tabs(["Login", "Sign Up"])

        with tab1:
            st.subheader("🔐 Login")
            username = st.text_input("Username", key="login_username")
            password = st.text_input("Password", type="password", key="login_password")

            if st.button("Login"):
                if authenticate(conn, username, password):
                    st.session_state.authenticated = True
                    st.session_state.username = username
                    st.session_state.session_id = os.urandom(16).hex()
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid credentials")

        with tab2:
            st.subheader("📝 Sign Up")
            new_username = st.text_input("New Username", key="signup_username")
            new_password = st.text_input("New Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password", key="confirm_password")

            if st.button("Sign Up"):
                if new_password != confirm_password:
                    st.error("Passwords do not match")
                elif register_user(conn, new_username, new_password):
                    st.success("Registration successful! Please login.")

    else:
        # Main application UI
        st.title("Document Search System")

        # File upload section
        st.header("📤 Upload Documents")
        uploaded_files = st.file_uploader(
            "Choose files to upload",
            accept_multiple_files=True,
            key="file_uploader"
        )

        if uploaded_files:
            with st.spinner("Processing files..."):
                for file in uploaded_files:
                    process_and_upload_file(conn, file)

        # Search section
        st.header("🔍 Search Documents")
        query = st.text_area("Enter your search query:")

        if st.button("Search"):
            if query:
                with st.spinner("Searching..."):
                    results = get_similar_chunks_search_service(query)
                    # Display search results
                    if results:
                        st.markdown("### Most Relevant Chunks")
                        for result in results:
                            st.markdown(f"**Document: {result['relative_path']}**")
                            st.markdown(f"**Chunk Size:** {result['size']} bytes")
                            st.markdown(result['chunk'])
                            st.markdown("---")
                    else:
                        st.info("No relevant chunks found")
            else:
                st.warning("Please enter a search query")

        # Logout button
        if st.sidebar.button("Logout"):
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()

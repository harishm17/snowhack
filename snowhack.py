import streamlit as st
import snowflake.connector
from snowflake.connector.errors import ProgrammingError
import os

def init_snowflake_connection():
    """Initialize Snowflake connection with credentials"""
    try:
        conn = snowflake.connector.connect(
            user='SNOWHACK10',
            password='Snowhack10',
            account='nrdbnwt-qob04556',
            warehouse='COMPUTE_WH',
            database='SAMPLEDATA',
            schema='PUBLIC'
        )
        return conn
    except Exception as e:
        st.error(f"Failed to connect to Snowflake: {str(e)}")
        return None

def list_stages(conn):
    """List all stages in the current schema"""
    try:
        cursor = conn.cursor()
        cursor.execute("SHOW STAGES")
        stages = cursor.fetchall()
        return stages
    except ProgrammingError as e:
        st.error(f"Error listing stages: {str(e)}")
        return []
    finally:
        cursor.close()

def upload_files_to_stage(conn, stage_name, files):
    """Upload multiple files to a specific Snowflake stage"""
    for file in files:
        try:
            cursor = conn.cursor()
            
            # Save uploaded file locally
            file_path = f"./{file.name}"
            with open(file_path, "wb") as f:
                f.write(file.getbuffer())
            
            # Use PUT command to upload the file to the stage without compression
            put_command = f"PUT 'file://{file_path}' @{stage_name} AUTO_COMPRESS=FALSE"
            cursor.execute(put_command)
            st.success(f"File {file.name} successfully uploaded to stage {stage_name}.")
            
            # Clean up local file after upload
            os.remove(file_path)
        
        except ProgrammingError as e:
            st.error(f"Error uploading file {file.name} to stage {stage_name}: {str(e)}")
        finally:
            cursor.close()

def list_files_in_stage(conn, stage_name):
    """List all files in a specific stage"""
    try:
        cursor = conn.cursor()
        cursor.execute(f"LIST @{stage_name}")
        files = cursor.fetchall()
        return files
    except ProgrammingError as e:
        st.error(f"Error listing files in stage {stage_name}: {str(e)}")
        return []
    finally:
        cursor.close()

# Streamlit app
st.title("Snowflake Stage Explorer & Multi-File Uploader")

# Initialize connection
conn = init_snowflake_connection()

if conn:
    # List all stages
    stages = list_stages(conn)
    
    if stages:
        # Create a selection box for stages
        stage_names = [stage[1] for stage in stages]  # Assuming stage name is the second column
        selected_stage = st.selectbox("Select a stage to upload files:", stage_names)
        
        if selected_stage:
            # Multiple file uploader
            uploaded_files = st.file_uploader(
                "Choose files to upload", accept_multiple_files=True
            )
            
            if uploaded_files:
                st.write(f"Uploading {len(uploaded_files)} files to stage `{selected_stage}`...")
                upload_files_to_stage(conn, selected_stage, uploaded_files)
            
            st.subheader(f"Files in {selected_stage}")
            
            # List files in the selected stage
            files = list_files_in_stage(conn, selected_stage)
            
            if files:
                # Create a dataframe to display file information
                file_data = []
                for file in files:
                    file_data.append({
                        "Name": file[0],
                        "Size (bytes)": file[1],
                        "Last Modified": file[2]
                    })
                
                st.dataframe(file_data)
            else:
                st.info("No files found in this stage.")



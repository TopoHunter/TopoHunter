# This file is a script to clear data when encountered failures
import pymysql
import common
import os
import subprocess

def check_and_create_database(host, user, password, database_name, sql_file_path, grant_user, grant_host):
    connection = pymysql.connect(host=host, user=user, password=password)
    cursor = connection.cursor()
    try:
        cursor.execute(f"SHOW DATABASES LIKE '{database_name}';")
        result = cursor.fetchone()
        if result:
            print(f"Database '{database_name}' already exists.")
        else:
            cursor.execute(f"CREATE DATABASE {database_name};")
            print(f"Database '{database_name}' created.")
            cursor.execute(f"GRANT ALL PRIVILEGES ON {database_name}.* TO '{grant_user}'@'{grant_host}';")
            cursor.execute("FLUSH PRIVILEGES;")
            print(f"Granted all privileges on '{database_name}' to '{grant_user}'@'{grant_host}'.")
        command = f"sudo mysql -h {host} -u {user} -p{password} {database_name} < {sql_file_path}"
        process = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if process.returncode == 0:
            print(f"SQL file '{sql_file_path}' executed successfully.")
        else:
            print(f"Failed to execute SQL file. Error: {process.stderr.decode()}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    finally:
        cursor.close()
        connection.close()


if __name__ == '__main__':
    common.parse_config()
    check_and_create_database(
        host=common.MYSQL_HOST,
        user=common.MYSQL_USER,
        password=common.MYSQL_PASSWORD,
        database_name=common.MYSQL_DATABASE,
        sql_file_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "create_table_binary.sql"),
        grant_user=common.MYSQL_USER,
        grant_host=common.MYSQL_HOST
    )
    output_files = [os.path.join(common.OUTPUT_DIR, f) for f in os.listdir(common.OUTPUT_DIR) if f != "placeholder"]
    if len(output_files) > 0:
        for f in output_files:
            cmd = ["rm", "-f", f]
            subprocess.run(cmd)
        print("Removed files in output dir")
    else:
        print("Output dir is empty")
    zip_files = [os.path.join(os.path.dirname(os.path.abspath(__file__)), f) for f in os.listdir(os.path.dirname(os.path.abspath(__file__))) if f.endswith(".zip")]
    if len(zip_files) > 0:
        for f in zip_files:
            cmd = ["rm", "-f", f]
            subprocess.run(cmd)
        print("Removed zip files")
    else:
        print("No zip files")

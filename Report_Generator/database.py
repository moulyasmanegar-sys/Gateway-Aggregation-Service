import mysql.connector
from mysql.connector import Error


DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "Chitty@6543",
    "database": "security_analysis"
}


def get_db_connection():

    try:

        connection = mysql.connector.connect(**DB_CONFIG)

        if connection.is_connected():

            print("MySQL connected successfully")

        return connection

    except Error as e:

        print("MySQL connection error:", e)

        return None


def save_report(report):

    connection = get_db_connection()

    if connection is None:
        return False

    cursor = connection.cursor()

    try:

        query = """
            INSERT INTO reports (
                indicator,
                indicator_type,
                risk_score,
                risk_level,
                verdict,
                action,
                recommendation
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """

        values = (
            report["indicator"],
            report["indicator_type"],
            report["risk_score"],
            report["risk_level"],
            report["verdict"],
            report["action"],
            report["recommendation"]
        )

        cursor.execute(query, values)

        connection.commit()

        print("Report saved successfully!")

        return True

    except Error as e:

        print("Error saving report:", e)

        connection.rollback()

        return False

    finally:

        cursor.close()
        connection.close()
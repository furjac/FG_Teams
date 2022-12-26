import os
import shutil
import sqlite3
from contextlib import closing
from datetime import datetime


def create_database(database, database_backup):
    with closing(sqlite3.connect(database)) as connection:
        with closing(connection.cursor()) as cursor:
            cursor.execute("""CREATE TABLE IF NOT EXISTS
            statistics (date TEXT, view INTEGER)""")

            connection.commit()

    try:
        os.remove(database_backup)
    except Exception:
        pass

    try:
        shutil.copy(database, database_backup)
    except Exception:
        pass


def update_database(database, threads, increment=1):
    today = str(datetime.today().date())
    with closing(sqlite3.connect(database, timeout=threads*10)) as connection:
        with closing(connection.cursor()) as cursor:
            try:
                cursor.execute(
                    "SELECT view FROM statistics WHERE date = ?", (today,))
                previous_count = cursor.fetchone()[0]
                cursor.execute("UPDATE statistics SET view = ? WHERE date = ?",
                               (previous_count + increment, today))
            except Exception:
                cursor.execute(
                    "INSERT INTO statistics VALUES (?, ?)", (today, 0),)

            connection.commit()

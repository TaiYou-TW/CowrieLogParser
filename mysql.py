"""
MySQL output connector. Writes audit logs to MySQL database
"""


import MySQLdb

from twisted.enterprise import adbapi
from twisted.internet import defer
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig

SPECIFY_FILE_LIST_FILENAME = "./files.txt"
files = []
table = CowrieConfig.get("output_mysql", "table")


def openFile():
    with open(SPECIFY_FILE_LIST_FILENAME, mode="r") as f:
        lines = f.readlines()
        for line in lines:
            files.append(line.replace("\n", ""))
        f.close()


def find_sensitive_files(command):
    global files

    if len(files) == 0:
        openFile()

    found_files = []
    commands = command.split(" ")

    if len(commands) > 1:
        for idx in range(1, len(commands)):
            paths = commands[idx].split("/")
            counter = len(paths) - 1
            filename = paths[counter]
            while filename == "" and counter >= 0:
                counter -= 1
                filename = paths[counter]

            if filename != "" and filename in files:
                found_files.append(filename)

    return found_files


class ReconnectingConnectionPool(adbapi.ConnectionPool):
    """
    Reconnecting adbapi connection pool for MySQL.

    This class improves on the solution posted at
    http://www.gelens.org/2008/09/12/reinitializing-twisted-connectionpool/
    by checking exceptions by error code and only disconnecting the current
    connection instead of all of them.

    Also see:
    http://twistedmatrix.com/pipermail/twisted-python/2009-July/020007.html
    """

    def _runInteraction(self, interaction, *args, **kw):
        try:
            return adbapi.ConnectionPool._runInteraction(self, interaction, *args, **kw)
        except (MySQLdb.OperationalError, MySQLdb._exceptions.OperationalError) as e:
            if e.args[0] not in (2003, 2006, 2013):
                raise e
            log.msg(f"RCP: got error {e}, retrying operation")
            conn = self.connections.get(self.threadID())
            self.disconnect(conn)
            # Try the interaction again
            return adbapi.ConnectionPool._runInteraction(self, interaction, *args, **kw)


class Output(cowrie.core.output.Output):
    """
    mysql output
    """

    db = None
    debug: bool = False

    def start(self):
        self.debug = CowrieConfig.getboolean("output_mysql", "debug", fallback=False)
        port = CowrieConfig.getint("output_mysql", "port", fallback=3306)
        try:
            self.db = ReconnectingConnectionPool(
                "MySQLdb",
                host=CowrieConfig.get("output_mysql", "host"),
                db=CowrieConfig.get("output_mysql", "database"),
                user=CowrieConfig.get("output_mysql", "username"),
                passwd=CowrieConfig.get("output_mysql", "password", raw=True),
                port=port,
                cp_min=1,
                cp_max=1,
                charset="utf8mb4",
                cp_reconnect=True,
                use_unicode=True,
            )
        except (MySQLdb.Error, MySQLdb._exceptions.Error) as e:
            log.msg(f"output_mysql: Error {e.args[0]}: {e.args[1]}")

    def stop(self):
        self.db.commit()
        self.db.close()

    def sqlerror(self, error):
        """
        1146, "Table '...' doesn't exist"
        1406, "Data too long for column '...' at row ..."
        """
        if error.value.args[0] in (1146, 1406):
            log.msg(f"output_mysql: MySQL Error: {error.value.args!r}")
            log.msg("MySQL schema maybe misconfigured, doublecheck database!")
        else:
            log.msg(f"output_mysql: MySQL Error: {error.value.args!r}")

    def simpleQuery(self, sql, args):
        """
        Just run a deferred sql query, only care about errors
        """
        if self.debug:
            log.msg(f"output_mysql: MySQL query: {sql} {args!r}")
        d = self.db.runQuery(sql, args)
        d.addErrback(self.sqlerror)

    @defer.inlineCallbacks
    def write(self, entry):
        global table

        if entry["eventid"] == "cowrie.session.connect":
            self.simpleQuery(
                "INSERT INTO `" + table + "` (`session`, `timestamp`, `ip`, `type`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s)",
                (entry["session"], entry["time"], entry["src_ip"], "connect"),
            )

        elif entry["eventid"] == "cowrie.login.success":
            self.simpleQuery(
                "INSERT INTO `"
                + table
                + "` (`session`, `timestamp`, `ip`, `type`, `information`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    entry["session"],
                    entry["time"],
                    entry["src_ip"],
                    "loginSuccess",
                    f'{{"username":"{entry["username"]}","password":{entry["password"]}}}',
                ),
            )

        elif entry["eventid"] == "cowrie.login.failed":
            self.simpleQuery(
                "INSERT INTO `"
                + table
                + "` (`session`, `timestamp`, `ip`, `type`, `information`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    entry["session"],
                    entry["time"],
                    entry["src_ip"],
                    "loginFailed",
                    f'{{"username":"{entry["username"]}","password":{entry["password"]}}}',
                ),
            )

        elif entry["eventid"] == "cowrie.command.input":
            self.simpleQuery(
                "INSERT INTO `"
                + table
                + "` (`session`, `timestamp`, `ip`, `type`, `information`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    entry["session"],
                    entry["time"],
                    entry["src_ip"],
                    "command",
                    entry["input"],
                ),
            )

            found_files = find_sensitive_files(entry["input"])
            if found_files:
                self.simpleQuery(
                    "INSERT INTO `"
                    + table
                    + "` (`session`, `timestamp`, `ip`, `type`, `information`) "
                    "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                    (
                        entry["session"],
                        entry["time"],
                        entry["src_ip"],
                        "sensitiveFiles",
                        found_files,
                    ),
                )

        elif entry["eventid"] == "cowrie.command.failed":
            self.simpleQuery(
                "INSERT INTO `"
                + table
                + "` (`session`, `timestamp`, `ip`, `type`, `information`) "
                "VALUES (%s, FROM_UNIXTIME(%s), %s, %s, %s)",
                (
                    entry["session"],
                    entry["time"],
                    entry["src_ip"],
                    "commandFailed",
                    entry["input"],
                ),
            )

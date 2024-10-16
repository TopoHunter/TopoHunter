import pymysql
import common
import time


class DBConn:
    def __init__(self):
        self.conn = self.get_db_conn()
        self.cursor = self.conn.cursor()

    def get_db_conn(self):
        conn = pymysql.connect(host=common.MYSQL_HOST, user=common.MYSQL_USER,
                               password=common.MYSQL_PASSWORD, database=common.MYSQL_DATABASE)
        return conn

    def insert_nodes(self, nodes: list, opr_id: int, host_id: int):
        common.get_logger().debug('Saving Traceroute Results of Nodes (%d Nodes) in Database...' %
                                  len(nodes))
        SQL = """
        INSERT IGNORE INTO Node (node_addr, target_addr, discovered_time, opr_id, host_id)
        VALUES (%s, %s, %s, %s, %s)
        """

        params = []
        for node in nodes:
            params.append((node[0], node[1], node[2], opr_id, host_id))

        max_tries = 5
        while True:
            ok = True
            max_tries -= 1
            try:
                self.cursor.executemany(SQL, params)
                self.conn.commit()
            except Exception as e:
                if e.args[0] in (2006, 2013):
                    common.get_logger().error("Connection dropped, reconnecting...")
                    self.conn = self.get_db_conn()
                    self.cursor = self.conn.cursor()
                    return
                common.get_logger().error("Failed to Insert Nodes: %s, %d times to retry" %
                                          (e, max_tries))
                self.conn.rollback()
                ok = False
            finally:
                if ok or max_tries <= 0:
                    break
                time.sleep(5)

        common.get_logger().debug('Traceroute Results of Nodes (%d Nodes) Saved in Database' %
                                  len(nodes))
        return
    
    def get_nodes(self, opr_id: int, host_id: int):
        SQL = """
        SELECT node_addr, target_addr FROM Node WHERE opr_id = %s AND host_id = %s
        """
        max_tries = 5
        while True:
            ok = True
            max_tries -= 1
            try:
                self.cursor.execute(SQL, (opr_id, host_id))
            except Exception as e:
                if e.args[0] in (2006, 2013):
                    common.get_logger().error("Connection dropped, reconnecting...")
                    self.conn = self.get_db_conn()
                    self.cursor = self.conn.cursor()
                    return []
                common.get_logger().error("Failed to Get Nodes: %s, %d time(s) to retry" %
                                          (e, max_tries))
                ok = False
            finally:
                if ok or max_tries <= 0:
                    break
                time.sleep(5)
        try:
            results = self.cursor.fetchall()
            records = [list(row) for row in results]
            return records
        except:
            return []

    def insert_edges(self, edges: list, opr_id: int, host_id: int):
        SQL = """
        INSERT INTO Edge (src_addr, dst_addr, hop_distance, target_addr, discovered_time, opr_id, host_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
        hop_distance = IF(VALUES(hop_distance) < hop_distance, VALUES(hop_distance), hop_distance),
        target_addr = IF(VALUES(hop_distance) < hop_distance, VALUES(target_addr), target_addr),
        discovered_time = IF(VALUES(hop_distance) < hop_distance, VALUES(discovered_time), discovered_time),
        opr_id = IF(VALUES(hop_distance) < hop_distance, VALUES(opr_id), opr_id),
        host_id = IF(VALUES(hop_distance) < hop_distance, VALUES(host_id), host_id)
        """
        params = []
        for edge in edges:
            params.append((edge[0], edge[1], edge[2], edge[3], edge[4], opr_id, host_id))
        max_tries = 5
        while True:
            ok = True
            max_tries -= 1
            try:
                self.cursor.executemany(SQL, params)
                self.conn.commit()
            except Exception as e:
                if e.args[0] in (2006, 2013):
                    common.get_logger().error("Connection dropped, reconnecting...")
                    self.conn = self.get_db_conn()
                    self.cursor = self.conn.cursor()
                    return
                common.get_logger().error("Failed to Insert Edges: %s, %d times to retry" %
                                          (e, max_tries))
                self.conn.rollback()
                ok = False
            finally:
                if ok or max_tries <= 0:
                    break
                time.sleep(5)
        return
    
    def get_edges(self, opr_id: int, host_id: int):
        SQL = """
        SELECT src_addr, dst_addr, hop_distance, target_addr FROM Edge WHERE opr_id = %s AND host_id = %s
        """
        max_tries = 5
        while True:
            ok = True
            max_tries -= 1
            try:
                self.cursor.execute(SQL, (opr_id, host_id))
            except Exception as e:
                if e.args[0] in (2006, 2013):
                    common.get_logger().error("Connection dropped, reconnecting...")
                    self.conn = self.get_db_conn()
                    self.cursor = self.conn.cursor()
                    return []
                common.get_logger().error("Failed to Get Edges: %s, %d time(s) to retry" %
                                          (e, max_tries))
                ok = False
            finally:
                if ok or max_tries <= 0:
                    break
                time.sleep(5)
        try:
            results = self.cursor.fetchall()
            records = [list(row) for row in results]
            return records
        except:
            return []
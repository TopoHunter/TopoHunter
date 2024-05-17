from neo4j import GraphDatabase
import common
import time


class Neo4jConn:
    def __init__(self):
        self.driver = GraphDatabase.driver(common.NEO4J_URL, auth=(
            common.NEO4J_USERNAME, common.NEO4J_PASSWORD))
        self.database = common.NEO4J_DATABASE

    @staticmethod
    def _insert_edges_transaction(tx: GraphDatabase.driver, edges: list, opr_id: int, ip_version: int = 4):
        if ip_version == 4:
            tx.run('''
            WITH $edges as batch
            UNWIND batch as edge
            MERGE (node1: IPv4Node {name:edge.src}) 
            MERGE (node2: IPv4Node {name:edge.dst}) 
            MERGE (node1)-[e:IPv4Edge]->(node2) ON CREATE SET e.opr_id = $opr_id, e.hop_distance = edge.hop_distance ON MATCH SET e.opr_id = CASE WHEN edge.hop_distance < e.hop_distance THEN $opr_id ELSE e.opr_id END, e.hop_distance = CASE WHEN edge.hop_distance < e.hop_distance THEN edge.hop_distance ELSE e.hop_distance END
            ''', edges=edges, opr_id=opr_id)
        else:
            tx.run('''
            WITH $edges as batch
            UNWIND batch as edge
            MERGE (node1: IPv6Node {name:edge.src}) 
            MERGE (node2: IPv6Node {name:edge.dst}) 
            MERGE (node1)-[e:IPv6Edge]->(node2) ON CREATE SET e.opr_id = $opr_id, e.hop_distance = edge.hop_distance ON MATCH SET e.opr_id = CASE WHEN edge.hop_distance < e.hop_distance THEN $opr_id ELSE e.opr_id END, e.hop_distance = CASE WHEN edge.hop_distance < e.hop_distance THEN edge.hop_distance ELSE e.hop_distance END
            ''', edges=edges, opr_id=opr_id)

    def insert_edges(self, edges: list, opr_id: int, ip_version: int = 4):
        common.get_logger().debug('Saving Traceroute Results of Edges (%d Edges) in Database...' %
                                  len(edges))
        max_tries = 5
        while True:
            ok = True
            max_tries -= 1
            try:
                with self.driver.session(database=self.database) as session:
                    session.write_transaction(
                        Neo4jConn._insert_edges_transaction, edges, opr_id, ip_version)
            except Exception as e:
                common.get_logger().error(
                    "Failed to Insert Edges: %s, %d time(s) to retry" % (e, max_tries))
                ok = False
            finally:
                if ok or max_tries <= 0:
                    break
                time.sleep(5)

        common.get_logger().debug('Traceroute Results of Edges (%d Edges) Saved in Database' %
                                  len(edges))

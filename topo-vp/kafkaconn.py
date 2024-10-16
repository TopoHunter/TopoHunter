from kafka import KafkaConsumer
from kafka import KafkaProducer
import json
import common

'''
bin/zookeeper-server-start.sh config/zookeeper.properties
bin/kafka-server-start.sh config/server.properties

bin/kafka-topics.sh --create --partitions 1 --replication-factor 1 --topic <topic name> --bootstrap-server localhost:9092
bin/kafka-topics.sh --describe --topic <topic name> --bootstrap-server localhost:9092

bin/kafka-console-producer.sh --topic <topic name> --bootstrap-server localhost:9092
bin/kafka-console-consumer.sh --topic <topic name> --from-beginning --bootstrap-server localhost:9092

Messages:

traceroute

{
    "type": "traceroute",
    "task_id": "feuyewqc13",
    "host": ["1.1.1.1", "2.2.2.2"],
    "timestamp": "1639385394",
}


traceroute-result
{
    "type": "traceroute-result",
    "host": "123.123.123.123",
    "timestamp", "1639385394",
    "result":
    [
        ["1.1.1.1", "2.2.2.2"],
        ["2.2.2.2", "3.3.3.3"],
        ["3.3.3.3", "4.4.4.4"],
    ]
}



'''


class KafkaConn:
    def __init__(self, prober_name):
        self.prober_name = prober_name
        self.cmd_consumer = KafkaConsumer(common.KAFKA_COMMAND_TOPIC + "-" + self.prober_name,
                                      bootstrap_servers=[common.KAFKA_SERVER])
        self.cmd_producer = KafkaProducer(bootstrap_servers=[
                                      common.KAFKA_SERVER], value_serializer=lambda v: json.dumps(v).encode('utf-8'))
        self.res_consumer = KafkaConsumer(common.KAFKA_RESULT_TOPIC + "-" + self.prober_name,
                                      bootstrap_servers=[common.KAFKA_SERVER])
        self.res_producer = KafkaProducer(bootstrap_servers=[
                                      common.KAFKA_SERVER], value_serializer=lambda v: json.dumps(v).encode('utf-8'), retries=5, retry_backoff_ms=3000, request_timeout_ms=300000, compression_type='gzip')

    def start(self):
        for msg in self.res_consumer:
            self.process(msg.value)

    def process(self, msg: bytes, func: callable):
        msg_dict = json.loads(msg)
        func(msg_dict)
    
    def res(self, res: dict):
        try:
            self.res_producer.send(common.KAFKA_RESULT_TOPIC + "-" + self.prober_name, res)
            self.res_producer.flush()
        except Exception as e:
            common.get_logger().error('Failed to Send Result Messages to Kafka: %s', e)


if __name__ == '__main__':
    kafkaconn = KafkaConn()
    kafkaconn.start()

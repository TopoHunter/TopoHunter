# Install Python Packages
sudo apt-get install gcc libgraphviz-dev pkg-config
`pip3 install -r requirements.txt`

# Kafka
## Start Kafka Service

```
bin/zookeeper-server-start.sh -daemon config/zookeeper.properties
bin/kafka-server-start.sh -daemon config/server.properties
```

## Create Topics

```
bin/kafka-topics.sh --create --partitions 1 --replication-factor 1 --bootstrap-server [2001::1]:9092 --topic topo-command-topic
bin/kafka-topics.sh --create --partitions 1 --replication-factor 1 --bootstrap-server [2001::1]:9092 --topic topo-result-topic

```

## Test Kafka Topics
### Describe Topics
```
bin/kafka-topics.sh --describe --topic <topic-name> --bootstrap-server [2001:1234::1]:9092
```

### Delete Topic messages
```
bin/kafka-topics.sh --bootstrap-server [2001::1]:9092 --delete --topic topo-command-topic
bin/kafka-topics.sh --bootstrap-server [2001::1]:9092 --delete --topic topo-command-topic
```
### Show Command Messages
```
bin/kafka-console-consumer.sh --topic topo-command-topic  --from-beginning --bootstrap-server [2001:1234::1]:9092
bin/kafka-console-consumer.sh --topic topo-command-topic  --from-beginning --bootstrap-server [2001::1]:9092
```

### Send Messages
```
bin/kafka-console-producer.sh --topic <topic name> --bootstrap-server [2001:1234::1]:9092
bin/kafka-console-producer.sh --topic topo-command-topic --bootstrap-server [2001::1]:9092
```

## Kafka Messages

### traceroute
```
{
    "type": "traceroute",
    "opr_id": 4455,
    "host": ["1.1.1.1", "2.2.2.2"],
}
```

### traceroute result
```
traceroute-result
{
    "type": "traceroute-result",
    "host": "123.123.123.123",
    "opr_id": 4455,
    "edges":
    [
        {"src":"1.1.1.1", "dst":"2.2.2.2", "real":1, "target":"8.8.8.8"}，
        {"src":"2.2.2.2", "dst":"3.3.3.3", "real":1, "target":"8.8.8.8"}，
        {"src":"3.3.3.3", "dst":"4.4.4.4", "real":0, "target":"9.9.9.9"}
    ],
    "nodes":
    [
        {"addr":"1.1.1.1", "rttl":60, "target": "8.8.8.8"},
        {"addr":"2.2.2.2", "rttl":52, "target": "9.9.9.9}
    ],
    <"finished": 1> (optional)
}
```

# Redis
Install and start:
```
sudo apt install redis-server
sudo service redis start
```

Configure remote access:
```
sudo vim /etc/redis/redis.conf
注释掉bind 127.0.0.1 :: 1
将protected-mode yes改为protected-mode no
sudo service redis restart
```

Data Format:
```
key:
    <opr_id>:target
value:
    "<target1>\n<target2>\n..."
```

```
key:
    <opr_id>:status
value:
    key: 
        <host1>
    value:
        "S" | "P" | "F" | "C" (Submitted, Processing, Finished, Completed)
    key: 
        <host2>
    value:
        "S" | "P" | "F" | "C"
    key: 
        <host3>
    value:
        "S" | "P" | "F" | "C"
    ...
```

# MySQL
Create Tables:
sudo mysql
```
create database Topo;
create user 'mysql'@'localhost' identified by 'gww123123';
grant all privileges on Topo.* to 'mysql'@'localhost';
use Topo;
source createTable.sql;
```

# Neo4j
Install:
```
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable 4.4' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt list -a neo4j
```

Add Neo4j Restraints:
```
CREATE CONSTRAINT ON (node: IPv4Node) assert node.name is unique;
CREATE CONSTRAINT ON (node: IPv6Node) assert node.name is unique;
```


# Clean-Up
```
MATCH (n) DETACH DELETE n;
FLUSHDB
source clean.sql
```

# Usage (Specify your measurement method and targets by modifying `topo-shell.py`)
```
python3 topo-server.py
python3 topo-shell.py 
```
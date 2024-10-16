import logging
import os
import configparser

EXP_ID = ''
TYPE_TRACEROUTE4 = 1
TYPE_TRACEROUTE6 = 2
MSG_TYPE_TRACEROUTE4 = 'traceroute4'
MSG_TYPE_TRACEROUTE4_RESULT = 'traceroute4-result'
MSG_TYPE_TRACEROUTE6 = 'traceroute6'
MSG_TYPE_TRACEROUTE6_RESULT = 'traceroute6-result'
MSG_TYPE_STOP = 'stop'
KAFKA_SERVER = ''
KAFKA_COMMAND_TOPIC = 'topo-command-topic'
KAFKA_RESULT_TOPIC = 'topo-result-topic'
REDIS_SERVER = ''
REDIS_PORT = -1
MYSQL_HOST = ''
MYSQL_USER = ''
MYSQL_PASSWORD = ''
MYSQL_DATABASE = ''
VP_NAME = ''
INTERFACE_NAME = ''
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.cfg')
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
LOG_FILE = ''
IPASN_FILE = ''
ALIASED_PREFIXES_FILE = ''
DY6_PATH = ''
DY6_INPUT_FILE = os.path.join(DATA_DIR, "dy6_input.txt")
DY6_OUTPUT_FILE = os.path.join(OUTPUT_DIR, "dy6_output_%d_%s.yrp")
DY6_PCAP_FILE = os.path.join(OUTPUT_DIR, "pcap_%d_%s.pcap")
DY6_EXCEPTION_FILE = os.path.join(OUTPUT_DIR, "exception_%d_%s.pcap")

def parse_config():
    global EXP_ID
    global TYPE_TRACEROUTE4
    global TYPE_TRACEROUTE6
    global MSG_TYPE_TRACEROUTE4
    global MSG_TYPE_TRACEROUTE4_RESULT
    global MSG_TYPE_TRACEROUTE6
    global MSG_TYPE_TRACEROUTE6_RESULT
    global KAFKA_SERVER
    global KAFKA_COMMAND_TOPIC
    global KAFKA_RESULT_TOPIC
    global REDIS_SERVER
    global REDIS_PORT
    global MYSQL_HOST
    global MYSQL_USER
    global MYSQL_PASSWORD
    global MYSQL_DATABASE
    global VP_NAME
    global INTERFACE_NAME
    global CONFIG_FILE
    global DATA_DIR
    global OUTPUT_DIR
    global LOG_FILE
    global IPASN_FILE
    global ALIASED_PREFIXES_FILE
    global DY6_PATH
    global DY6_INPUT_FILE
    global DY6_OUTPUT_FILE
    global DY6_PCAP_FILE
    global DY6_EXCEPTION_FILE

    variables = globals()
    try:
        config_parser = configparser.ConfigParser()
        config_parser.read(CONFIG_FILE)
        exp_cfg = config_parser['exp']
        for parameter in ('EXP_ID', 'IPASN_FILE', 'ALIASED_PREFIXES_FILE'):
            variables[parameter] = exp_cfg[parameter]
        dy6_cfg = config_parser['dy6']
        for parameter in ('DY6_PATH',):
            variables[parameter] = dy6_cfg[parameter]
        network_cfg = config_parser['network']
        for parameter in ('VP_NAME', 'INTERFACE_NAME'):
            variables[parameter] = network_cfg[parameter]
        kafka_cfg = config_parser['kafka']
        for parameter in ('KAFKA_SERVER',):
            variables[parameter] = kafka_cfg[parameter]
        redis_cfg = config_parser['redis']
        for parameter in ('REDIS_SERVER',):
            variables[parameter] = redis_cfg[parameter]
        for parameter in ('REDIS_PORT',):
            variables[parameter] = int(redis_cfg[parameter])
        mysql_cfg = config_parser['mysql']
        for parameter in ('MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE'):
            variables[parameter] = mysql_cfg[parameter]
        LOG_FILE = os.path.join(OUTPUT_DIR, f"{EXP_ID}_{VP_NAME}.log")
    except Exception as e:
        get_logger().error("Failure in Parsing Config: %s", e)

logger = None
def get_logger() -> logging.Logger:
    global logger
    if logger is None:
        logging.basicConfig(
            level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        logger = logging.getLogger(__name__)
        handler = logging.FileHandler(LOG_FILE)
        handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(fmt=formatter)
        logger.addHandler(handler)
    return logger

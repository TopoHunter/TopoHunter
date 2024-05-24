import logging
import os
import configparser

DIR_PATH = os.path.dirname(os.path.abspath(__file__))

CONFIG_DIR = os.path.join(DIR_PATH, 'config.cfg')

TYPE_TRACEROUTE4 = 1
TYPE_TRACEROUTE6 = 2
MSG_TYPE_TRACEROUTE4 = 'traceroute4'
MSG_TYPE_TRACEROUTE4_RESULT = 'traceroute4-result'
MSG_TYPE_TRACEROUTE6 = 'traceroute6'
MSG_TYPE_TRACEROUTE6_RESULT = 'traceroute6-result'

# Experiment Settings
# ----------------------------------------
EXP_NUM = 0
EXP_DATA_DIR = os.path.join(DIR_PATH, "exp_" + str(EXP_NUM))
LOG_FILE = os.path.join(EXP_DATA_DIR, "log.log")
IPASN_FILE = os.path.join(DIR_PATH, "data", "ipasn.dat")
ALIASED_PREFIXES_FILE = os.path.join(DIR_PATH, "data", "aliased_prefixes.txt")
# ----------------------------------------

# Server Configs
# ----------------------------------------
KAFKA_SERVER = ''
KAFKA_COMMAND_TOPIC = ''
KAFKA_RESULT_TOPIC = ''
REDIS_SERVER = ''
REDIS_PORT = 6379
# ----------------------------------------

# Vantage Point Configs
# ----------------------------------------
VP_NAME = ''
LOCAL_IPV4_ADDR = ''
LOCAL_IPV6_ADDR = ''
YARRP_DIR = ''
YARRP_INPUT_DIR = os.path.join(DIR_PATH, "data", "yarrp_input.txt")
YARRP_OUTPUT_DIR = os.path.join(DIR_PATH, "data", "yarrp_output_%d_%s.txt")
PCAP_OUTPUT_DIR = os.path.join(DIR_PATH, "data", "pcap_%d_%s.pcap")
INTERFACE_NAME = ''
MYSQL_HOST = ''
MYSQL_USER = ''
MYSQL_PASSWORD = ''
MYSQL_DATABASE = ''
# ----------------------------------------


def parse_config():
    global YARRP_DIR
    global INTERFACE_NAME
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
    global LOCAL_IPV4_ADDR
    global LOCAL_IPV6_ADDR

    variables = globals()

    try:
        config_parser = configparser.ConfigParser()
        config_parser.read(CONFIG_DIR)

        yarrp_cfg = config_parser['yarrp']
        for parameter in ('YARRP_DIR', 'INTERFACE_NAME'):
            variables[parameter] = yarrp_cfg[parameter]

        server_cfg = config_parser['server']
        for parameter in ['KAFKA_SERVER', 'KAFKA_COMMAND_TOPIC', 'KAFKA_RESULT_TOPIC', 'REDIS_SERVER', 'REDIS_PORT']:
            variables[parameter] = server_cfg[parameter]
            
        mysql_cfg = config_parser['mysql']
        for parameter in ('MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE'):
            variables[parameter] = mysql_cfg[parameter]
            
        vp_cfg = config_parser['vp']
        for parameter in ('VP_NAME', 'LOCAL_IPV4_ADDR', 'LOCAL_IPV6_ADDR'):
            variables[parameter] = vp_cfg[parameter]
        os.makedirs(EXP_DATA_DIR, exist_ok=True)

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

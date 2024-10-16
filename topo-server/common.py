import logging
import json
import configparser
import os

EXP_ID = ''
EXP_DATA_DIR = ''
OUTPUT_DIR = ''
LOG_FILE = ''
IPASN_FILE = ''
HITLIST_Z48_FILE = ''
HITLIST_Z64_FILE = ''
ALIASED_PREFIXES_FILE = ''

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

# NEO4J_URL = ''
# NEO4J_USERNAME = ''
# NEO4J_PASSWORD = ''
# NEO4J_DATABASE = ''

MYSQL_HOST = ''
MYSQL_USER = ''
MYSQL_PASSWORD = ''
MYSQL_DATABASE = ''

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.cfg')
VP_INFO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vp_info.json')
VP_DICT = {}

# hyper parameters
TREE_LEAF_PREFIX_LEN = 48
POINT_PER_NODE = 5
POINT_PER_EDGE = 1
VALUE_TREE_RANDOM = 0.1
DECAY_RATE = 0.1
CUT_THRESHOLD = 0
CUT_PROBED_TIMES = 16
TARGETS_NUM_PER_OPR = 50000
MAX_PACKETS_NUM_PER_VP = 400000000
MAX_ZERO_POINT_ROUNDS = 5
# ----------------------------------------

def parse_config():
    global EXP_ID
    global EXP_DATA_DIR
    global OUTPUT_DIR
    global LOG_FILE
    global EXP_DATA_DIR
    global IPASN_FILE
    global HITLIST_Z48_FILE
    global HITLIST_Z64_FILE
    global ALIASED_PREFIXES_FILE

    global KAFKA_SERVER
    global KAFKA_COMMAND_TOPIC
    global KAFKA_RESULT_TOPIC

    global REDIS_SERVER
    global REDIS_PORT
    
    global MYSQL_HOST 
    global MYSQL_USER 
    global MYSQL_PASSWORD
    global MYSQL_DATABASE

    global CONFIG_FILE
    global VP_INFO_FILE
    global VP_DICT

    global TREE_LEAF_PREFIX_LEN
    global POINT_PER_NODE
    global POINT_PER_EDGE
    global VALUE_TREE_RANDOM
    global DECAY_RATE
    global CUT_THRESHOLD
    global CUT_PROBED_TIMES
    global TARGETS_NUM_PER_OPR
    global MAX_PACKETS_NUM_PER_VP
    global MAX_ZERO_POINT_ROUNDS

    variables = globals()

    try:
        config_parser = configparser.ConfigParser()
        config_parser.read(CONFIG_FILE)
        exp_cfg = config_parser['exp']
        for parameter in ('EXP_ID', 'IPASN_FILE', 'HITLIST_Z48_FILE', 'HITLIST_Z64_FILE', 'ALIASED_PREFIXES_FILE', 'OUTPUT_DIR'):
            variables[parameter] = exp_cfg[parameter]
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
        hyper_cfg = config_parser['hyper']
        for parameter in ('TREE_LEAF_PREFIX_LEN', 'CUT_PROBED_TIMES', 'TARGETS_NUM_PER_OPR', 'MAX_PACKETS_NUM_PER_VP', 'MAX_ZERO_POINT_ROUNDS'):
            variables[parameter] = int(hyper_cfg[parameter])
        for parameter in ('POINT_PER_NODE', 'POINT_PER_EDGE', 'VALUE_TREE_RANDOM', 'DECAY_RATE'):
            variables[parameter] = float(hyper_cfg[parameter])
        EXP_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"exp_{EXP_ID}")
        LOG_FILE = os.path.join(EXP_DATA_DIR, f"{EXP_ID}.log")
        os.makedirs(EXP_DATA_DIR, exist_ok=True)
        OUTPUT_DIR = os.path.join(OUTPUT_DIR, EXP_ID)
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        with open(VP_INFO_FILE, "r") as f:
            VP_DICT = json.load(f)
        if POINT_PER_EDGE == 0:
            CUT_THRESHOLD = POINT_PER_NODE * ((1 - DECAY_RATE) ** CUT_PROBED_TIMES)
        else:
            CUT_THRESHOLD = min(POINT_PER_NODE, POINT_PER_EDGE) * ((1 - DECAY_RATE) ** CUT_PROBED_TIMES)
    except Exception as e:
        get_logger().error("Failure in Parsing Config: %s", e)
        
logger = None

def get_logger()->logging.Logger:
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
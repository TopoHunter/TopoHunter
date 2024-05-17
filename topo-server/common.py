import logging
import configparser
import os

EXP_NUM = 0

TYPE_TRACEROUTE4 = 1
TYPE_TRACEROUTE6 = 2

MSG_TYPE_TRACEROUTE4 = 'traceroute4'
MSG_TYPE_TRACEROUTE4_RESULT = 'traceroute4-result'

MSG_TYPE_TRACEROUTE6 = 'traceroute6'
MSG_TYPE_TRACEROUTE6_RESULT = 'traceroute6-result'

KAFKA_SERVER = '[server-ip]:9092'
KAFKA_COMMAND_TOPIC = 'topo-command-topic'
KAFKA_RESULT_TOPIC = 'topo-result-topic'

REDIS_SERVER = 'localhost'
REDIS_PORT = 6379

CONFIG_DIR = 'config.cfg'

# Server-side Only
# ----------------------------------------
GEODB_DIR = './data/GeoLite2-City.mmdb'

NEO4J_URL = ''
NEO4J_USERNAME = ''
NEO4J_PASSWORD = ''
NEO4J_DATABASE = ''

PROBER_DICT = { "<prober>": [0, "<prober-ip>"] }

MYSQL_HOST = ''
MYSQL_USER = ''
MYSQL_PASSWORD = ''
MYSQL_DATABASE = ''

EXP_DATA_DIR = os.path.join(os.path.dirname(__file__), "exp_" + str(EXP_NUM))
LOG_FILE = os.path.join(EXP_DATA_DIR, "log.log")

TREE_LEAF_PREFIX_LEN = 48
POINT_PER_NODE = 5
POINT_PER_EDGE = 1
VALUE_TREE_RANDOM = 0.1
DECAY_RATE = 0.1
CUT_PROBED_TIMES = 16
TARGETS_NUM_PER_OPR = 50000
MAX_PACKETS_NUM_PER_PROBER = 400000000
IPASN_FILE = os.path.join(os.path.dirname(__file__), "data", "ipasn.dat")
SEED_PREFIXES_FILE = os.path.join(os.path.dirname(__file__), "data", "seed_prefixes.txt")
WARMUP_TARGETS_FILE = os.path.join(os.path.dirname(__file__), "data", "warmup_addresses.txt")
ALIASED_FILE = os.path.join(os.path.dirname(__file__), "data", "aliased_prefixes.txt")
OUTPUTS_DIR = os.path.join(os.path.join("<outputs_root_path>", str(EXP_NUM)))
# ----------------------------------------

def parse_config():
    global EXP_NUM
    global NEO4J_URL
    global NEO4J_USERNAME
    global NEO4J_PASSWORD
    global NEO4J_DATABASE
    
    global PROBER_DICT
    
    global MYSQL_HOST 
    global MYSQL_USER 
    global MYSQL_PASSWORD
    global MYSQL_DATABASE
    
    global EXP_DATA_DIR
    global LOG_FILE
    global TREE_LEAF_PREFIX_LEN
    global POINT_PER_NODE
    global POINT_PER_EDGE
    global VALUE_TREE_STOP
    global DECAY_RATE
    global TARGETS_NUM_PER_OPR
    global IPASN_FILE

    variables = globals()

    try:
        config_parser = configparser.ConfigParser()
        config_parser.read(CONFIG_DIR)

        neo4j_cfg = config_parser['neo4j']
        for parameter in ('NEO4J_URL', 'NEO4J_USERNAME', 'NEO4J_PASSWORD', 'NEO4J_DATABASE'):
            variables[parameter] = neo4j_cfg[parameter]
            
        prober_cfg = config_parser['prober']
        prober_names = prober_cfg['PROBERS'].split(",")
        variables['PROBER_DICT'] = {key: variables['PROBER_DICT'][key] for key in prober_names if key in variables['PROBER_DICT']}
            
        mysql_cfg = config_parser['mysql']
        for parameter in ('MYSQL_HOST', 'MYSQL_USER', 'MYSQL_PASSWORD', 'MYSQL_DATABASE'):
            variables[parameter] = mysql_cfg[parameter]
            
        os.makedirs(variables['EXP_DATA_DIR'], exist_ok=True)
        
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
import redis
import zlib
import common

class RedisConn:
    def __init__(self):
        self.conn = redis.StrictRedis(host=common.REDIS_SERVER, port=common.REDIS_PORT, decode_responses=True)
    
    def set(self, key:str, value:str, compress:bool=False):
        try:
            if compress:
                value = zlib.compress(value.encode("utf-8"))
            self.conn.set(key, value)
        except Exception as e:
            common.get_logger().error('Failed to Set Redis Key-Value: %s', e)
    
    def get(self, key:str, compress:bool=False)->str:
        try:
            ret = self.conn.get(key)
            if ret is not None:
                self.conn.expire(key, 10800)
                if compress:
                    ret = zlib.decompress(ret).decode("utf-8")
            return ret
        except Exception as e:
            common.get_logger().error('Failed to Get Redis Key-Value: %s', e)

    def set_status(self, opr_id:int, value:str):
        self.set(f"{common.VP_NAME}:{str(opr_id)}:status", value)

    def get_status(self, opr_id):
        return self.get(f"{common.VP_NAME}:{str(opr_id)}:status")

    def set_target(self, opr_id:int, value:str):
        self.set(f"{common.VP_NAME}:{str(opr_id)}:target", value, True)

    def get_target(self, opr_id:int):
        return self.get(f"{common.VP_NAME}:{str(opr_id)}:target", True)
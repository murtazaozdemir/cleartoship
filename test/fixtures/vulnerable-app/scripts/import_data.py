import pickle, yaml

def load_config(raw):
    return yaml.load(raw)          # CTS072: unsafe yaml.load

def restore(blob):
    return pickle.loads(blob)      # CTS072: pickle RCE

# Global configuration
from src.OCR_aided_siamese import *
from src.phishpedia_logo_detector.inference import *
from src.util.chrome import *

# element recognition model -- logo only
cfg_path = './src/phishpedia_logo_detector/configs/faster_rcnn.yaml'
weights_path = './src/phishpedia_logo_detector/output/rcnn_2/rcnn_bet365.pth'
ele_model = config_rcnn(cfg_path, weights_path, conf_threshold=0.05)

# siamese model
print('Load protected logo list')
pedia_model, logo_feat_list, file_name_list = phishpedia_config(num_classes=277,
                                                weights_path='./src/phishpedia_siamese/resnetv2_rgb_new.pth.tar',
                                                targetlist_path='./src/phishpedia_siamese/expand_targetlist/')
print('Finish loading protected logo list')

siamese_ts = 0.87 # FIXME: threshold is 0.87 in phish-discovery?

# brand-domain dictionary
domain_map_path = './src/phishpedia_siamese/domain_map.pkl'


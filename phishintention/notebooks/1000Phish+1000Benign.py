
from src.OCR_aided_siamese import *
from src.AWL_detector import *
from src.crp_classifier import *
from tqdm import tqdm
from src.PaddleOCR.tools.infer_rec import initialize_model, infer_img
import matplotlib.pyplot as plt
from PIL import Image
import Levenshtein

if __name__ == '__main__':

    # load domain map
    domain_map_path = './src/phishpedia/domain_map.pkl'
    with open(domain_map_path, 'rb') as handle:
        domain_map = pickle.load(handle)

    # load OCR model
    configs_file = './src/PaddleOCR/configs/rec/rec_r50_fpn_srn.yml'
    ocr_model, ocr_ops, ocr_post_process_class, logger = initialize_model(config_path=configs_file)

    logger.info('begin loading logo targetlist')
    pedia_model, logo_feat_list, file_name_list = phishpedia_config(num_classes=277,
                                                    weights_path='./src/phishpedia/resnetv2_rgb_new.pth.tar',
                                                    targetlist_path='./src/phishpedia/expand_targetlist/')
    logger.info('finish loading logo targetlist')

    ct = 0

    for path in tqdm(os.listdir('D:/ruofan/git_space/phishpedia/benchmark/Sampled 1000phish + 1000benign/Sampled_phish1000')):

        url = ''  # dummy value, not important
        img_path = 'D:/ruofan/git_space/phishpedia/benchmark/Sampled 1000phish + 1000benign/Sampled_phish1000/' + path + '/shot.png'
        annot = [x.strip().split(',') for x in
                 open('D:/ruofan/git_space/phishpedia/benchmark/Sampled 1000phish + 1000benign/phish1000_coord.txt').readlines()]

        # read labelled
        for c in annot:
            if c[0] == path:
                x1, y1, x2, y2 = map(float, c[1:])
                break
        pred_boxes = np.asarray([[x1, y1, x2, y2]])
        pred_classes = np.asarray([0.])

        img = Image.open(img_path)
        cropped_img = img.crop((x1, y1, x2, y2)) # in RGB format

        # get predicted targeted brand
        pred_target, _, _ = phishpedia_classifier(pred_classes=pred_classes, pred_boxes=pred_boxes,
                                                  domain_map_path=domain_map_path,
                                                  model=pedia_model,
                                                  logo_feat_list=logo_feat_list, file_name_list=file_name_list,
                                                  url=url,
                                                  shot_path=img_path,
                                                  ts=0.83)

        if pred_target is not None:
            results = infer_img(config_path=configs_file,
                                file=cropped_img,
                                model=ocr_model,
                                ops=ocr_ops,
                                post_process_class=ocr_post_process_class)
            plt.imshow(cropped_img)
            plt.show()

            if brand_converter(pred_target) == brand_converter(path.split('+')[0]):
                ct += 1
            # if results[0][1] <= 0.8:  # confidence is low
            #     logger.info('Confidence is too low {}'.format(results[0][1]))
            #     if brand_converter(pred_target) == brand_converter(path.split('+')[0]):
            #         print(brand_converter(pred_target) == brand_converter(path.split('+')[0]))
            #         ct += 1
            # else:
            #     test_text = results[0][0]
            #     logger.info(test_text)
            #     if brand_converter(pred_target) == brand_converter(path.split('+')[0]):
                    # additional check on text precision
                    # if Levenshtein.ratio(test_text, brand_converter(pred_target).lower()) > 0.5:
                    #     ct += 1
                    # else:
                    #     all_domains = domain_map[brand_converter(pred_target)]
                    #     for d in all_domains:
                    #         if Levenshtein.ratio(test_text, d) > 0.5:
                    #             ct += 1
                    #             break

print(ct, '/', len(os.listdir('D:/ruofan/git_space/phishpedia/benchmark/Sampled 1000phish + 1000benign/Sampled_phish1000')))
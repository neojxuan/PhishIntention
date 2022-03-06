import gspread
from oauth2client.service_account import ServiceAccountCredentials
import pandas as pd
import os
import shutil
from collections import Counter
from datetime import date, timedelta
import random
import numpy as np
random.seed(1234)


def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)

def findpaypal(result_txt):
    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_pos = [x for x in df if (len(x) >= 4) and (x[2] == '1')] # get reported phishing
    df_paypal = [x for x in df_pos if x[3]=='PayPal']
    print(result_txt)
    print(df_paypal)

def normal_eval(df_labels, df_labels2, target_folder):
    os.makedirs(target_folder, exist_ok=True)
    os.makedirs(os.path.join(target_folder, 'PhishIntention_TP'), exist_ok=True)
    os.makedirs(os.path.join(target_folder, 'Phishpedia_TP'), exist_ok=True)

    # Get breakdown statistics
    pedia_tp = []
    pedia_fp = []
    pedia_unsure = []

    intention_tp = []
    intention_miss = []
    intention_fp = []
    intention_unsure = []

    for index, row in df_labels.iterrows():
        path = row['date'] + '/' + row['foldername']
        print(path)
        if row['yes'] > 0 and row['no'] == 0:
            # phishpedia get it correct
            pedia_tp.append(path)
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path))  or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):  # intention also get it correct
                intention_tp.append(path)
            else:  # intention miss it
                intention_miss.append(path)
        elif row['no'] > 0 and row['yes'] == 0:
            # mistaken
            pedia_fp.append(path)
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path))  or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):  # intention also has this FP
                intention_fp.append(path)
            else:
                pass  # intention suppress this fp
        elif (row['unsure'] > 0) or (row['no'] > 0 and row['yes'] > 0):
            # unsure, ignore
            print('ignore')
            pedia_unsure.append(path)
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path))  or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):  # intention also has this FP
                intention_unsure.append(path)
        else:
            print('Not labelled yet {}'.format(path))

    # df_labels2 is labelling intention - pedia
    for index, row in df_labels2.iterrows():
        path = row['date'] + '/' + row['foldername']
        if row['yes'] > 0 and row['no'] == 0:
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path)) or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):
                intention_tp.append(path)
            else:
                print('FileNotFoundError')
        elif row['no'] > 0 and row['yes'] == 0:
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path))  or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):
                intention_fp.append(path)
            else:
                print('FileNotFoundError')

        elif (row['unsure'] > 0) or (row['no'] > 0 and row['yes'] > 0):
            if os.path.exists(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', path))  or os.path.exists(os.path.join('./datasets/PhishDiscovery/PhishIntention', path)):
                intention_unsure.append(path)
            else:
                print('FileNotFoundError')

        else:
            print('Not labelled yet {}'.format(path))

    # print out
    print('Pedia TP = {}, FP = {}, Unsure = {}'.format(str(len(pedia_tp)), str(len(pedia_fp)), str(len(pedia_unsure))))
    print('Intention TP = {}, FP = {}, Miss(FN) = {}, Unsure = {}'.format(str(len(intention_tp)), str(len(intention_fp)),
                                                                        str(len(intention_miss)), str(len(intention_unsure))))

    '''Save the data'''
    for tp in pedia_tp:
        try:
            shutil.copytree(os.path.join('./datasets/PhishDiscovery_2nd/Phishpedia', tp),
                  os.path.join(target_folder, 'Phishpedia_TP', tp.split('/')[-1]))
        except FileExistsError:
            continue
        except FileNotFoundError:
            pass
            # shutil.copytree(os.path.join('./datasets/PhishDiscovery/Phishpedia', tp),
            #       os.path.join(target_folder, 'Phishpedia_TP', tp.split('/')[-1]))
    for tp in intention_tp:
        try:
            shutil.copytree(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', tp),
              os.path.join(target_folder, 'PhishIntention_TP', tp.split('/')[-1]))
        except FileNotFoundError:
            pass
            # shutil.copytree(os.path.join('./datasets/PhishDiscovery/PhishIntention', tp),
            #   os.path.join(target_folder, 'PhishIntention_TP', tp.split('/')[-1]))
        except FileExistsError:
            continue
    for fp in intention_fp:
        try:
            shutil.copytree(os.path.join('./datasets/PhishDiscovery_2nd/PhishIntention', fp),
              os.path.join(target_folder, 'PhishIntention_FP', fp.split('/')[-1]))
        except FileExistsError:
            continue
        except FileNotFoundError:
            pass
            # shutil.copytree(os.path.join('./datasets/PhishDiscovery/PhishIntention', fp),
            #   os.path.join(target_folder, 'PhishIntention_FP', fp.split('/')[-1]))
    for fn in intention_miss:
        try:
            shutil.copytree(os.path.join('./datasets/PhishDiscovery_2nd/Phishpedia', fn),
              os.path.join(target_folder, 'PhishIntention_FN', fn.split('/')[-1]))
        except FileExistsError:
            continue
        except FileNotFoundError:
            pass
            # shutil.copytree(os.path.join('./datasets/PhishDiscovery/Phishpedia', fn),
            #   os.path.join(target_folder, 'PhishIntention_FN', fn.split('/')[-1]))
    #
    return pedia_tp, pedia_fp, pedia_unsure, intention_tp, intention_fp, intention_unsure, intention_miss
#
def save_zeroday_phish(result_txt, source_folder, target_folder, df_labels, df_labels2):
    '''
    Count zero day phishing
    '''

    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_pos = [x for x in df if (len(x) >= 3) and (x[2] == '1')] # get reported phishing
    os.makedirs(target_folder, exist_ok=True)

    # get entries
    folders = [x[0] for x in df_pos]
    urls = [x[1] for x in df_pos]
    vtresults = [x[5] for x in df_pos]

    # get vtscan corrected results
    print('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(os.path.basename(result_txt).split('.txt')[0]))
    if not os.path.exists('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(os.path.basename(result_txt).split('.txt')[0])):
        newvtresults = vtresults
    else:
        df_correct = pd.read_csv('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(os.path.basename(result_txt).split('.txt')[0]))
        newvtresults = []
        for i, r in enumerate(vtresults):
            if r == 'error':
                try:
                    newvtresults.append(list(df_correct[df_correct['url'] == urls[i]]['vtscan'])[0])
                except IndexError:
                    pass
            else:
                newvtresults.append(r)

    ct = 0
    zeroday_TP = []
    for k, vt in enumerate(newvtresults):
        if folders[k] not in os.listdir(source_folder):
            continue
        if int(vt.split('/')[0]) == 0: # zero-day
            print(folders[k])
            try:
                label_asphish = list(df_labels[df_labels['foldername'] == folders[k]]['yes'])[0]
            except IndexError as e:
                label_asphish = list(df_labels2[df_labels2['foldername'] == folders[k]]['yes'])[0]

            if label_asphish >= 1:
                try:
                    zeroday_TP.append(folders[k])
                    ct += 1
                    shutil.copytree(os.path.join(source_folder, folders[k]),
                                    os.path.join(target_folder, folders[k]))
                except FileExistsError as e:
                    print(e)
                    continue
                except Exception as e:
                    print(e)
                    continue

    print('Number of zero-day phishing:', ct)
    return zeroday_TP


def get_phishintention_dynamic(date, result_txt, df_labels, df_labels2):
    '''
    How many TPs are verified by dynamic analysis
    :param date:
    :param result_txt:
    :param df_labels:
    :param df_labels2:
    :return:
    '''
    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_dynamic = [x for x in df if (len(x) >= 7) and (x[2] == '1') and (x[6] == 'True')]

    # get entries
    folders = [x[0] for x in df_dynamic]

    # Count dynamic TPs
    ct_dynamic_TP = 0
    dynamic_TP = []

    for f in folders:
        if os.path.exists('./datasets/PhishDiscovery/PhishIntention/{}'.format(date)):
            if f not in os.listdir('./datasets/PhishDiscovery/PhishIntention/{}'.format(date)):
                continue
        elif os.path.exists('./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date)):
            if f not in os.listdir('./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date)):
                continue
        else:
            raise FileNotFoundError
        try:
            isphish = list(df_labels[df_labels['foldername'] == f]['yes'])[0]
            if isphish > 0:
                ct_dynamic_TP += 1
                dynamic_TP.append(f)
        except IndexError:
            isphish = list(df_labels2[df_labels2['foldername'] == f]['yes'])[0]
            if isphish > 0:
                ct_dynamic_TP += 1
                dynamic_TP.append(f)

    return dynamic_TP, ct_dynamic_TP


def get_phishintention_brands(date, result_txt, df_labels, df_labels2):
    '''
    Get predicted brand distribution
    :param date:
    :param result_txt:
    :param df_labels:
    :param df_labels2:
    :return:
    '''
    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_dynamic = [x for x in df if (len(x) >= 4) and (x[2] == '1')] # reported phishing

    # get entries
    folders = [x[0] for x in df_dynamic]
    pred_brands = [x[3] for x in df_dynamic] # predicted brands

    # Count dynamic TPs
    ct_dynamic_TP = 0
    pred_brands_TP = []
    folders_TP = [] # there are some duplicates, so need to return this as well

    for kk, f in enumerate(folders):
        if os.path.exists('./datasets/PhishDiscovery/PhishIntention/{}'.format(date)):
            if f not in os.listdir('./datasets/PhishDiscovery/PhishIntention/{}'.format(date)):
                continue
        elif os.path.exists('./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date)):
            if f not in os.listdir('./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date)):
                continue
        else:
            raise FileNotFoundError
        try:
            isphish = list(df_labels[df_labels['foldername'] == f]['yes'])[0]
            if isphish > 0: # it is TP
                ct_dynamic_TP += 1
                pred_brands_TP.append(pred_brands[kk])
                folders_TP.append(f)
        except IndexError:
            isphish = list(df_labels2[df_labels2['foldername'] == f]['yes'])[0]
            if isphish > 0: # it is TP
                ct_dynamic_TP += 1
                pred_brands_TP.append(pred_brands[kk])
                folders_TP.append(f)

    print(len(pred_brands_TP))
    return folders_TP, pred_brands_TP

if __name__ == '__main__':

    start_date = date(2021, 7, 1)
    end_date = date(2021, 7, 31)
    dynamic_ct = 0
    scope = ['https://spreadsheets.google.com/feeds',
             'https://www.googleapis.com/auth/drive']
    creds = ServiceAccountCredentials.from_json_keyfile_name('./tele/cred.json', scope)
    client = gspread.authorize(creds)

    # get google sheet phishintention labels for 1st month
    sheet = client.open("test").sheet1
    # Extract and print all of the values
    list_of_hashes = sheet.get_all_records()
    # third sheet for 2nd month
    sheet = client.open("discovery_label").sheet1
    # Extract and print all of the values
    list_of_hashes2 = sheet.get_all_records()
    df_labels = pd.DataFrame(list_of_hashes+list_of_hashes2)

    # second sheet which label intention - pedia for 1st month
    sheet = client.open("PhishIntention").worksheet('label')
    # Extract and print all of the values
    list_of_hashes = sheet.get_all_records()
    df_labels2 = pd.DataFrame(list_of_hashes)

    if os.path.exists('./datasets/PhishDiscovery_2nd/PhishIntention_TP'):
        shutil.rmtree('./datasets/PhishDiscovery_2nd/PhishIntention_TP')
    if os.path.exists('./datasets/PhishDiscovery_2nd/PhishIntention_FP'):
        shutil.rmtree('./datasets/PhishDiscovery_2nd/PhishIntention_FP')
    if os.path.exists('./datasets/PhishDiscovery_2nd/PhishIntention_FN'):
        shutil.rmtree('./datasets/PhishDiscovery_2nd/PhishIntention_FN')
    if os.path.exists('./datasets/PhishDiscovery_2nd/Phishpedia_TP'):
        shutil.rmtree('./datasets/PhishDiscovery_2nd/Phishpedia_TP')

    '''Count zero-day phishing'''
    # all_intention_zeroday_TP = []
    # all_pedia_zeroday_TP = []

    # start_date = date(2021, 4, 2)
    # end_date = date(2021, 5, 3)
    # for single_date in daterange(start_date, end_date):
    #     date_ = single_date.strftime("%Y-%m-%d")
    #     this_zerodayTP = save_zeroday_phish(result_txt='./{}.txt'.format(date_),
    #                        source_folder='./datasets/PhishDiscovery/PhishIntention/{}'.format(date_),
    #                        target_folder='./datasets/PhishDiscovery/zeroday/',
    #                        df_labels=df_labels,
    #                        df_labels2=df_labels2)
    #     this_zerodayTP_pedia = save_zeroday_phish(result_txt='./{}_pedia.txt'.format(date_),
    #                        source_folder='./datasets/PhishDiscovery/Phishpedia/{}'.format(date_),
    #                        target_folder='./datasets/PhishDiscovery/zeroday_pedia/',
    #                        df_labels=df_labels,
    #                        df_labels2=df_labels2)
    #
    #     all_intention_zeroday_TP.extend(this_zerodayTP)
    #     all_pedia_zeroday_TP.extend(this_zerodayTP_pedia)

    # start_date = date(2021, 7, 1)
    # end_date = date(2021, 7, 31)
    # for single_date in daterange(start_date, end_date):
    #     date_ = single_date.strftime("%Y-%m-%d")
    #     print(date_)
    #     this_zerodayTP = save_zeroday_phish(result_txt='./{}.txt'.format(date_),
    #                                         source_folder='./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(
    #                                             date_),
    #                                         target_folder='./datasets/PhishDiscovery_2nd/zeroday/',
    #                                         df_labels=df_labels,
    #                                         df_labels2=df_labels2)
    #     this_zerodayTP_pedia = save_zeroday_phish(result_txt='./{}_pedia.txt'.format(date_),
    #                                               source_folder='./datasets/PhishDiscovery_2nd/Phishpedia/{}'.format(
    #                                                   date_),
    #                                               target_folder='./datasets/PhishDiscovery_2nd/zeroday_pedia/',
    #                                               df_labels=df_labels,
    #                                               df_labels2=df_labels2)
    #
    #     all_intention_zeroday_TP.extend(this_zerodayTP)
    #     all_pedia_zeroday_TP.extend(this_zerodayTP_pedia)

    # print('Number of zero-day TP for phishintention', len(all_intention_zeroday_TP))
    # print('Number of zero-day TP for phishpedia',len(all_pedia_zeroday_TP))

    '''Count how many TP come from dynamic'''
    # start_date = date(2021, 4, 2)
    # end_date = date(2021, 7, 31)
    # for single_date in daterange(start_date, end_date):
    #     date_ = single_date.strftime("%Y-%m-%d")
    #     if not os.path.exists('./{}.txt'.format(date_)):
    #         continue
    #     dynamic_TP, ct_dynamic_TP = get_phishintention_dynamic(date=date_, result_txt='./{}.txt'.format(date_),
    #                                                            df_labels=df_labels, df_labels2=df_labels2)
    #     dynamic_ct += ct_dynamic_TP
    #
    # print('Number of TPs from dynamic: ', dynamic_ct)

    '''Get predicted brand distribution for TPs'''
    # all_pred_brands_TP = []
    # all_folders_TP = []
    # for single_date in daterange(start_date, end_date):
    #     date_ = single_date.strftime("%Y-%m-%d")
    #     if not os.path.exists('./{}.txt'.format(date_)):
    #         continue
    #     folders_TP, pred_brands_TP = get_phishintention_brands(date=date_, result_txt='./{}.txt'.format(date_),
    #                                                             df_labels=df_labels, df_labels2=df_labels2)
    #     all_folders_TP.extend(folders_TP)
    #     all_pred_brands_TP.extend(pred_brands_TP)
    #
    # brand_freq = pd.DataFrame({'folder_TP': all_folders_TP, 'pred_brand_TP': all_pred_brands_TP})
    # brand_freq = brand_freq.drop_duplicates(subset=['folder_TP'], keep='first')
    # print(len(brand_freq))
    # brand_freq = pd.DataFrame.from_dict(Counter(brand_freq['pred_brand_TP']), orient='index').reset_index()
    # brand_freq.columns = ['brand', 'freq']
    # brand_freq.to_csv('./datasets/PhishDiscovery/Pred_Brand_Distribution.csv', index=False)

    '''Get TP, FP for sampled 1000'''
    # pedia_tp, pedia_fp, pedia_unsure, intention_tp, intention_fp, intention_unsure, intention_miss = normal_eval(df_labels, df_labels2, target_folder='./datasets/Phishdiscovery_2nd/')

    # # FIXME: here we deliberately drop some FP from phishpedia
    # random.seed(1234)
    # pedia_fp = list(random.sample(pedia_fp, 1033))

    # print(len(set(pedia_tp).intersection(set(intention_tp))))
    # print(len(set(pedia_tp)- set(intention_tp)))
    # print(len(set(intention_tp)- set(pedia_tp)))

    # print(len(set(pedia_fp).intersection(set(intention_fp))))
    # print(len(set(pedia_fp) - set(intention_fp)))
    # print(len(set(intention_fp) - set(pedia_fp)))
    #
    # print('{} zeroday TPs, from all reported phishing for phishpedia'.format(np.sum([x.split('/')[1] in all_pedia_zeroday_TP for x in pedia_tp])))
    # print('{} zeroday TPs, from all reported phishing for phishintention'.format(np.sum([x.split('/')[1] in all_intention_zeroday_TP for x in intention_tp])))
    # for tp in pedia_tp:
    #     if tp.split('/')[1] in all_pedia_zeroday_TP:
    #         try:
    #             shutil.copytree(os.path.join('./datasets/PhishDiscovery/Phishpedia', tp),
    #                   os.path.join('./datasets/PhishDiscovery/', 'Phishpedia_zeroday', tp.split('/')[-1]))
    #         except FileExistsError:
    #             continue
    # for tp in intention_tp:
    #     if tp.split('/')[1] in all_intention_zeroday_TP:
    #         try:
    #             shutil.copytree(os.path.join('./datasets/PhishDiscovery/PhishIntention', tp),
    #               os.path.join('./datasets/PhishDiscovery/', 'PhishIntention_zeroday', tp.split('/')[-1]))
    #         except FileExistsError:
    #             continue

    '''Aggregate what are reported together, ignore unsure'''
    # all_pedia = pedia_fp + pedia_tp
    # all_intention = intention_fp + intention_tp
    # print(pedia_unsure)
    # print(intention_unsure)
    # print('Length of pedia {}'.format(len(all_pedia)))
    # print('Length of intention {}'.format(len(all_intention)))
    # #
    # # Downsample 1000 and compute again
    # random.seed(1234)
    # pedia1000 = random.sample(all_pedia, 1000)
    # intention1000 = random.sample(all_intention, 1000)
    # #
    # print('{} TPs, {} FPs, from 1000 samples for phishpedia'.format(np.sum([x in pedia_tp for x in pedia1000]), np.sum([x in pedia_fp for x in pedia1000])))
    # print('{} TPs, {} FPs, from 1000 samples for phishintention'.format(np.sum([x in intention_tp for x in intention1000]), np.sum([x in intention_fp for x in intention1000])))
    #
    # '''zero-day in sample1000'''
    # print('{} TPs, {} FPs, {} zeroday TPs from 1000 samples for phishpedia'.format(np.sum([x in pedia_tp for x in pedia1000]), np.sum([x in pedia_fp for x in pedia1000]), np.sum([x.split('/')[1] in all_pedia_zeroday_TP for x in pedia1000])))
    # print('{} TPs, {} FPs, {} zeroday TPs from 1000 samples for phishintention'.format(np.sum([x in intention_tp for x in intention1000]), np.sum([x in intention_fp for x in intention1000]), np.sum([x.split('/')[1] in all_intention_zeroday_TP for x in intention1000])))

    # print(len(set(pedia_fp).intersection(set(intention_fp))))
    # print(set(pedia_fp).intersection(set(intention_fp)))

    '''find a paypal phishing'''
    # for single_date in daterange(start_date, end_date):
    #     date = single_date.strftime("%Y-%m-%d")
    #     findpaypal('./{}.txt'.format(date))
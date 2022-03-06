
import os
import shutil
import pandas as pd
import numpy as np
from datetime import date, timedelta
from src.util.chrome import vt_scan
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from collections import Counter
import time

def daterange(start_date, end_date):
    for n in range(int((end_date - start_date).days)):
        yield start_date + timedelta(n)

def get_vtscan4pos(result_txt):
    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_pos = [x for x in df if (len(x) >= 5) and (x[2] == '1')]
    print('Number of reported positive: {}'.format(len(df_pos)))

    urls = [x[1] for x in df_pos]
    vtresults = [x[5] for x in df_pos]
    return_df = pd.DataFrame({'url':urls, 'vtscan':vtresults})
    return return_df



def save_pos_site(result_txt, source_folder, target_folder):
    '''
    Save reported positive sites
    :param result_txt: txt path for phish-discovery results
    :param source_folder: data folder
    :param target_folder: folder to save positive sites
    :return:
    '''
    # df = pd.read_table(result_txt, encoding='ISO-8859-1')
    # df_pos = df.loc[df['phish'] == 1]
    df = [x.strip().split('\t') for x in open(result_txt, encoding='ISO-8859-1').readlines()]
    df_pos = [x for x in df if (len(x) >= 3) and (x[2] == '1')]
    print('Number of reported positive: {}'.format(len(df_pos)))

    if len(df_pos) == 0:
        return
    os.makedirs(target_folder, exist_ok=True)
    # for folder in list(df_pos['folder']):
    for folder in [x[0] for x in df_pos]:
        if 'autodiscover' == folder.split('.')[0] or 'outlook' == folder.split('.')[0]: # FIXME: filter out those webmail service
            continue
        try:
            shutil.copytree(os.path.join(source_folder, folder),
                        os.path.join(target_folder, folder))
        except FileExistsError as e:
            print(e)
            continue
        except FileNotFoundError as e:
            print(e)
            continue
        except Exception as e:
            print(e)
            continue


def get_diff(bigger_folder, smaller_folder, target_folder):
    '''
    Get set(bigger_folder) - set(smaller_folder)
    :param bigger_folder:
    :param smaller_folder:
    :param target_folder: folder to save diff sites
    :return:
    '''
    os.makedirs(target_folder, exist_ok=True)
    for folder in os.listdir(bigger_folder):
        if folder not in os.listdir(smaller_folder):
            try:
                shutil.copytree(os.path.join(bigger_folder, folder),
                                os.path.join(target_folder, folder))
            except FileExistsError:
                continue
            except FileNotFoundError:
                continue

def update_intention_new(intention_diff_folder):
    '''Update phishintention reported on gsheet'''
    scope = ['https://spreadsheets.google.com/feeds',
             'https://www.googleapis.com/auth/drive']
    creds = ServiceAccountCredentials.from_json_keyfile_name('./tele/cred.json', scope)
    client = gspread.authorize(creds)

    # second sheet which label intention - pedia for 1st month
    spreadsheet = client.open("PhishIntention")
    sheet = spreadsheet.worksheet('label')

    df = pd.DataFrame(sheet.get_all_records())
    cur_total = len(df)+1
    cur_folders = list(df['foldername'])
    print(cur_total)

    values = []
    for date in os.listdir(intention_diff_folder):
        for folder in os.listdir(os.path.join(intention_diff_folder, date)):
            if folder in cur_folders:
                pass
            else:
                url = open(os.path.join(intention_diff_folder, date, folder, 'info.txt')).read()
                value = [date, url, folder, 0, 0, 0]
                values.append(value)

    rng = "'" + sheet._properties['title'] + "'!A{}".format(cur_total+1)
    spreadsheet.values_update(rng, params={'valueInputOption': 'USER_ENTERED'}, body={'values': values})

def ct_dynamic(result_txt):
    '''
    Count how many go through dynamic
    :param result_txt:
    :return:
    '''
    results = open(result_txt, encoding='ISO-8859-1').readlines()[1:]
    runtimes = []
    for x in results:
        try:
            runtimes.append(float(x.split('\t')[-2].split('|')[-1]))
        except:
            pass
    return np.sum(np.array(runtimes) > 0), len(results)

def get_runtime(result_txt, from_pedia=False):
    '''
    Get 5-number summary statistics for runtime
    :param result_txt:
    :return:
    '''
    if not from_pedia:
        df = pd.read_table(result_txt, encoding='ISO-8859-1')
        runtime_list = list(df['runtime (layout detector|siamese|crp classifier|login finder total|login finder process)'])
        totaltime_list = list(df['total_runtime'])

        for i, x in enumerate(runtime_list):
            if isinstance(x, float):
                print(i, x)

        breakdown = [list(map(float, x.split('|'))) for x in runtime_list if not isinstance(x, float)]
        breakdown_df = pd.DataFrame(breakdown)
        breakdown_df.columns = ['layout', 'siamese', 'crp', 'dynamic', 'dynamic_partial']
        breakdown_df = breakdown_df.replace(0, np.NaN)
        print('Minimum: \n', breakdown_df.min(), '\n',
              'Median: \n', breakdown_df.median(), '\n',
              'Mean: \n', breakdown_df.mean(), '\n',
              'Maximum: \n', breakdown_df.max(), '\n')
    else:
        df = pd.read_table(result_txt, encoding='ISO-8859-1')
        totaltime_list = np.asarray(list(df['runtime']))

    print('Total time Min|Median|Mean|Max: \n')
    print(np.nanmin(totaltime_list), np.nanmedian(totaltime_list), np.nanmean(totaltime_list), np.nanmax(totaltime_list))


def get_count(date):
    count_pedia = len(os.listdir('./datasets/PhishDiscovery/Phishpedia/{}'.format(date)))
    count_intention = len(os.listdir('./datasets/PhishDiscovery/PhishIntention/{}'.format(date)))

    print('Phishpedia ct', count_pedia)
    print('Phishintention ct', count_intention)


if __name__ == '__main__':
    '''Save reported phishing'''
    # ct_dy = 0
    # ct_total = 0
    start_date = date(2022, 1, 7)
    end_date = date(2022, 1, 11)
    for single_date in daterange(start_date, end_date):
        date_ = single_date.strftime("%Y-%m-%d")
    #     try:
    #         ct_dy_this, ct_total_this = ct_dynamic('./{}.txt'.format(date_))
    #     except:
    #         continue
    #     print(date_, ct_dy_this, ct_total_this)
    #     ct_dy += ct_dy_this
    #     ct_total += ct_total_this
    #
    # start_date = date(2021, 7, 1)
    # end_date = date(2021, 7, 31)
    # for single_date in daterange(start_date, end_date):
    #     date_ = single_date.strftime("%Y-%m-%d")
    #     try:
    #         ct_dy_this, ct_total_this = ct_dynamic('./{}.txt'.format(date_))
    #     except:
    #         continue
    #     print(date_, ct_dy_this, ct_total_this)
    #     ct_dy += ct_dy_this
    #     ct_total += ct_total_this
    #
    # print(ct_dy, ct_total)

    #     # for phishpedia
    #     save_pos_site('./{}_pedia.txt'.format(date), 'Z:\\{}'.format(date), #TODO: move to Y: disk
    #                   './datasets/PhishDiscovery/Phishpedia/{}'.format(date))
    #     save_pos_site('./{}_pedia.txt'.format(date), 'Y:\\{}'.format(date), #TODO: move to Y: disk
                      # './datasets/PhishDiscovery/Phishpedia/{}'.format(date))
    #
        # for phishintention
        try:
            save_pos_site('./{}.txt'.format(date_), 'E:\\screenshots_rf\\{}'.format(date_),
                      './datasets/PhishIntention_3rd/{}'.format(date_))
        except FileNotFoundError:
            continue
    #
    #     # for phishpedia
    #     save_pos_site('./{}_pedia.txt'.format(date), 'E:\\screenshots_rf\\{}'.format(date),
    #                   './datasets/PhishDiscovery_2nd/Phishpedia/{}'.format(date))
    # #
    # #     # for phishintention
    #     save_pos_site('./{}.txt'.format(date), 'E:\\screenshots_rf\\{}'.format(date),
    #                   './datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date))
    # #
    #     # get phishintention - phishpedia
    #     get_diff(target_folder='./datasets/PhishDiscovery_2nd/intention_pedia_diff/{}'.format(date),
    #              smaller_folder='./datasets/PhishDiscovery_2nd/Phishpedia/{}'.format(date),
    #              bigger_folder='./datasets/PhishDiscovery_2nd/PhishIntention/{}'.format(date))

    # single_date = '2021-07-10'
    # get_runtime('./{}.txt'.format(single_date))
    # get_runtime('./{}_pedia.txt'.format(single_date), from_pedia=True)

    # get_count(date)
    # update_intention_new(intention_diff_folder='./datasets/PhishDiscovery_2nd/intention_pedia_diff')

    '''VTscan error correction'''
    # start_date = date(2021, 7, 28)
    # end_date = date(2021, 7, 31)
    # for single_date in daterange(start_date, end_date):
    #     date = single_date.strftime("%Y-%m-%d")
    #     print(date)
    #     # df = get_vtscan4pos('./{}.txt'.format(date))
    #     df = get_vtscan4pos('./{}_pedia.txt'.format(date))
    #     df_error = df[df['vtscan'] == 'error']
    #     if len(df_error) > 0:
    #         # df_error.to_csv('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(date), index=None)
    #         df_error.to_csv('./datasets/phishdiscovery_vtscan_error_{}_pedia.csv'.format(date), index=None) #FIXME: two models
    #         print(df_error)
    #
    # for single_date in daterange(start_date, end_date):
    #     date = single_date.strftime("%Y-%m-%d")
    #     # if not os.path.exists('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(date)):
    #     if not os.path.exists('./datasets/phishdiscovery_vtscan_error_{}_pedia.csv'.format(date)):
    #         continue
    #     # df_error = pd.read_csv('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(date))
    #     df_error = pd.read_csv('./datasets/phishdiscovery_vtscan_error_{}_pedia.csv'.format(date))
    #     for index, row in df_error.iterrows():
    #         if row['vtscan'] == "error":
    #             url = row['url']
    #             print(url)
    #             vt_result = "None"
    #             try:
    #                 if vt_scan(url) is not None:
    #                     positive, total = vt_scan(url)
    #                     print("Positive VT scan!")
    #                     vt_result = str(positive) + "/" + str(total)
    #                 else:
    #                     print("Negative VT scan!")
    #                     vt_result = "None"
    #
    #             except Exception as e:
    #                 print(e)
    #                 print('VTScan is not working...')
    #                 vt_result = "error"
    #             row['vtscan'] = vt_result
    #             time.sleep(15)
    #
    #     # df_error.to_csv('./datasets/phishdiscovery_vtscan_error_{}.csv'.format(date), index=None)
    #     df_error.to_csv('./datasets/phishdiscovery_vtscan_error_{}_pedia.csv'.format(date), index=None)
    #

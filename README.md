# PhishIntention

## PhishIntention
- This is the official implementation of "Inferring Phishing Intention via Webpage Appearance and Dynamics: A Deep Vision Based Approach"USENIX'22 [link to paper](), [link to our website](https://sites.google.com/view/phishintention/home)
- The contributions of our paper:
   - [x] We propose a referenced-based phishing detection system that captures both brand intention and credential-taking intention. To the best of our knowledge, is the first work which analyzes both brand intention and credential-taking intentions in a systematic way for phishing detection.
   - [x] We address various technical challenges in detecting the intentions by orchestrating multiple deep learning models. By design, our system is robust against misleading legitimacies and HTML obfuscation attack.
   - [x] We conduct extensive experiments to evaluate our system. The experiments evaluate the overall and step-wise effectiveness, robustness against various adversarial attacks, and usefulness in practice.
   - [x] We implement our system with a phishing monitoring system. It reports phishing webpages per day with the highest precision in comparison to the state-of-the-art phishing detection solutions.
    
## Framework
    
<img src="big_pic/Screenshot 2021-08-13 at 9.15.56 PM.png" style="width:2000px;height:350px"/>

```Input```: a screenshot, ```Output```: Phish/Benign, Phishing target
- Step 1: Enter <b>Abstract Layout detector</b>, get predicted elements

- Step 2: Enter <b>Siamese Logo Comparison</b>
    - If Siamese report no target, ```Return  Benign, None```
    - Else Siamese report a target, Enter step 3 <b>CRP classifier</b>
       
- Step 3: <b>CRP classifier</b>
   - If <b>CRP classifier</b> reports its a CRP page, go to step 5 <b>Return</b>
   - ElIf not a CRP page and havent execute <b>CRP Locator</b> before, go to step 4: <b>CRP Locator</b>
   - Else not a CRP page but have done <b>CRP Locator</b> before, ```Return Benign, None``` 

- Step 4: <b>CRP Locator</b>
   - Find login/signup links and click, if reach a CRP page at the end, go back to step 1 <b>Abstract Layout detector</b> with updated URL and screenshot
   - Else cannot reach a CRP page, ```Return Benign, None``` 
   
- Step 5: 
    - If reach a CRP + Siamese report target: ```Return Phish, Phishing target``` 
    - Else ```Return Benign, None``` 
    
    
## Requirements
The following packages may need to install manually.
- Windows/Linux/Mac machine 
- python=3.7 
- torch=1.6.0 # Make sure that the Pytorch is compatible with your CUDA version.
- torchvision
- Install compatible Detectron2 manually, see the [official installation guide](https://detectron2.readthedocs.io/en/latest/tutorials/install.html). If you are using Windows, try this [guide](https://dgmaxime.medium.com/how-to-easily-install-detectron2-on-windows-10-39186139101c) instead.


## Use it as a package
First install the requirements, then run
```
 pip install git+https://github.com/lindsey98/PhishIntention.git
```
In python
```python
from phishintention.phishintention_main import test
import matplotlib.pyplot as plt
from phishpedia.phishpedia_config import load_config

url = open("phishpedia/datasets/test_sites/accounts.g.cdcde.com/info.txt").read().strip()
screenshot_path = "phishpedia/datasets/test_sites/accounts.g.cdcde.com/shot.png"
cfg_path = None # None means use default config.yaml
ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH = load_config(cfg_path)

phish_category, pred_target, plotvis, siamese_conf, pred_boxes = test(url, screenshot_path,
                                                                      ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH)

print('Phishing (1) or Benign (0) ?', phish_category)
print('What is its targeted brand if it is a phishing ?', pred_target)
print('What is the siamese matching confidence ?', siamese_conf)
print('Where is the predicted logo (in [x_min, y_min, x_max, y_max])?', pred_boxes)
plt.imshow(plotvis[:, :, ::-1])
plt.title("Predicted screenshot with annotations")
plt.show()
```

## Use it as a repository
First install the requirements
Then, run
```
pip install -r requirements.txt
```
Please see detailed instructions in [phishintention/README.md](phishintention/README.md)


## Miscellaneous
- In our paper, we also implement several phishing detection and identification baselines, see [here](https://github.com/lindsey98/PhishingBaseline)
- We did not include the certstream code in this repo, our code is basically the same as [phish_catcher](https://github.com/x0rz/phishing_catcher), we lower the score threshold to be 40 to process more suspicious websites, readers can refer to their repo for details
- We also did not include the crawling script in this repo, readers can use [Selenium](https://selenium-python.readthedocs.io/), [Scrapy](https://github.com/scrapy/scrapy) or any web-crawling API to crawl the domains obtained from Cerstream, just make sure that the crawled websites are stored in [this format](https://github.com/lindsey98/Phishpedia/tree/main/datasets/test_sites)


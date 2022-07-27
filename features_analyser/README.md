# **Fishing the Phish**
*Integrative Team Project - IS Team 16 AY22*

# Features Analyser
As part of approach 2, there was a need to automate the analysis of the features of phishing kits. 

# Installation
```
git clone https://github.com/JustAyce/ITPTEAM16.git
cd ITPTEAM16
pip install -r requirements.txt
cd features_analyser
```

## Key files/directories to note
```
.
├── features/
│       │
│       └── content.py ----- # content features functions
│       └── domain.py ----- # domain features functions
│       └── url_analysis.py ----- # url features functions
│
│
├── util/
│     │
│     └── util.py ------ # utility functions
│
│
├── offline.py --------------------- # For usage on phishing │kits
│
└── online.py --------------------- # For usage on online websites
```

# User Manual
The features analyser is split into two different functions, offline and online.

## Offline

Before running the script, the following variables have to be modified.
| Variable Name    | Description | Example Value |
| ---------------- | ----------- | ------------- |
| phishing_kit_fp  | The file path of the phishing kit folder. | /home/user/phishing_kits |
| clustered_csv_fp | The file path of the csv obtained from clustering with KMeans. | clustered.csv |
| export_csv_fp    | The file path where the output csv should be saved to. | cluster_with_features.csv |

To perform features analysis on phishing kits, run offline.py with the following by:

```
python offline.py
```

## Online

Before running the script, the following variables have to be modified.
| Variable Name    | Description | Example Value |
| ---------------- | ----------- | ------------- |
| url_list_url     | The URL of the list of websites. Should be a text file. | https://openphish.com/feed.txt |


To perform features analysis on online websites, run online.py with the following by:

```
python online.py
```

# Features
<details>
<summary>Click to extend</summary>

| Feature | Description | Return Value |
| ------- | ----------- | ------------ |
| Suspicious Keywords | With a self-made wordlist of suspicious keywords, we identify the number of suspicious keywords on the website. <br> Examples of suspicious keywords include: "Urgent", "Now", "Locked". | len(sus_kw) | 
| Hyperlinks Count | The total number of hyperlinks on the website. | len(hyperlinks) |
| External & Empty Hyperlinks Count | The number of: <br> 1. Empty Hyperlinks ('#') <br> 2. External Hyperlinks | len(ext_empty_hyperlinks_count) |
| Image Count | The number of images on the website. | len(image_count)
| Image External Request URL Count | The number of images on the website that are loaded from external resources. | len(img_external_request_url_count) |
| External Favicon | Whether the website loads its favicon from an external resource. | True: 1 <br> False: 0 |
| Domain not in Title | Whether the domain is in the website's title. | True: 1 <br> False: 0 |
| IDN homograph | Whether the url of the website contains deceiving words. For more information, see [IDN Homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack) | True: 1 <br> False: 0 |
| Number of subdomains | The number of subdomains in the url. | len(subdomains) |
| TLD in subdomain | Whether the subdomains of the url contain TLDs, such as com, net. List of TLDs is obtained from [IANA](https://data.iana.org/TLD/tlds-alpha-by-domain.txt) | True: 1 <br> False: 0 | 
| Length of URL | Whether the length of the url exceeds 54. | True: 1 <br> False: 0 |
| Hyphen Count | The number of hyphens in the url. | len(hyphen_len) | 
| Typosquatted URL | Whether the url contains typosquatted words. For detection, we calculate Jarowinkler distance against a list of top 500 brand names. For more information, see [Typosquatting](https://en.wikipedia.org/wiki/Typosquatting) | True: 1 <br> False: 0 |
| Special Char | Whether the url contains special characters such as: '@', '!', '#' | True: 1 <br> False: 0 |
| Fake WWW | Whether the url contains 'www' in its domain and/or subdomains. | True: 1 <br> False: 0 |
| Gibberish URL | Whether the url is gibberish. Utilising [Nostril](https://github.com/casics/nostril). | True: 1 <br> False: 0 |

</details>

# Credits:
* [openphish](https://openphish.com/)
# **Fishing the Phish**
*Integrative Team Project - IS Team 16 AY22*

## **The Team**
| Team Member | Student ID                  |
|-------------|-----------------------------|
| 2000963     | Khoirun Ilman Bin Kamarudin |
| 2001183     | Woo Kah Howe                |
| 2001209     | Lim Jin Tao Benjamin        |
| 2001804     | Levisha D/O Sasikumar       |
| 2002342     | Crystal Choo Jia Xian       |

# **1. Objective**
Phishing attack is one of the most common cyber attacks. Today phishing attackers use
software kits, called phishing kits, that provide ready-to-deploy packages. With the availability
of such kits, attackers need not any more require sophisticated technical knowledge or skills.
In this project, we plan to analyze hundreds of kits in a semi-automated or automated way, so
as to understand the underlying characteristics of phishing, the commonality across different
targets being phished, the evolution of the code base (and hence the attack), cloaking
techniques in use, etc.

# **2. Methodology**

## **2.1 Clustering**
The general idea of the project was to perform n-gram extraction of the source codes of phishing websites with [TF-IDF](https://en.wikipedia.org/wiki/Tf%E2%80%93idf) Vectorization, then with KMeans, cluster those phishing websites based on the n-grams extracted.

## **2.2. Predicting the cluster**

### Approach 1 
The code and usage instructions of this approach can be found in [KMeans.ipynb.](KMeans.ipynb)

With pickles, by saving the pre-fitted KMeans Model used to perform clustering, we are able to then also predict the clusters of new phishing websites, without having to re-fit the KMeans model.

### Approach 2 
The code and usage instructions of this approach can be found in [KNN.ipynb.](KNN.ipynb)

Approach 2 is a hybrid source code based clustering, feature based prediction model, where firstly, KMeans is used to cluster the dataset, then KNN is used to predict the cluster of the phishing website, based on its features. The features analysed can be found in [KNN Features.](#knn-features)

# Installation
```
git clone https://github.com/JustAyce/ITPTEAM16.git
cd ITPTEAM16
pip install -r requirements.txt
```

# User Manual
Alongside the code, detailed instructions are provided in the notebooks of the following approaches.

## Approach 1
[KMeans.ipynb](KMeans.ipynb)

## Approach 2
[KNN.ipynb](KNN.ipynb)

For the features analyser used as part of approach 2, please see [features_analyser](features_analyser)

# KNN Features
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
* [phishunt.io](https://github.com/0xDanielLopez/phishing_kits)

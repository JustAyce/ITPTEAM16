# ITPTEAM16

## The Team
| Team Member | Student ID                  | Grouping and Task |
|-------------|-----------------------------|-------------------|
| 2000963     | Khoirun Ilman Bin Kamarudin |                   |
| 2001183     | Woo Kah Howe                |                   |
| 2001209     | Lim Jin Tao Benjamin        |                   |
| 2001804     | Levisha D/O Sasikumar       |                   |
| 2002342     | Crystal Choo Jia Xian       |                   |


## KNN Factors
<details>
<summary>Click to extend</summary>

|         **Factors**         | **Category** |       **Example**      |                                                  **Rationale**                                                 |
|:---------------------------:|:------------:|:----------------------:|:--------------------------------------------------------------------------------------------------------------:|
| Fake Login                  | Content      | test@test.com          | Phishing websites will allow users not in the system to login                                                  |
| suspicious keyword in index | Content      | locked urgent          |                                                                                                                |
| Uptime of Web page          | Content      |                        | Phishing Websites host their website only when conducting their attack to maintain opsec                       |
| Hyperlinks                  | Content      | href: #                | Erroneous hyperlink Empty hyperlink Phishing website tend to have more external request to legitimate          |
| CA Reputation               | Domain       | LetsEncrypt vs ZeroSSL | Tend to choose CA that is profit driven and not check thoroughly                                               |
| Extended Certificate        | Domain       |                        | Operation will only last a short period of time, hence they do not need to pay extra to extend the certificate |
| Domain reg date             | Domain       |                        |                                                                                                                |
| DNS Record                  | Domain       |                        |                                                                                                                |
| End Date of Domain          | Domain       |                        |                                                                                                                |
| IDN Homograph               | URL          | akámai.com             |                                                                                                                |
| Number of sub domains       | URL          | facebook-loginlive.com |                                                                                                                |
| TLD as subdomain            | URL          | x.com.domain.net       |                                                                                                                |
| URL Length                  | URL          |                        |                                                                                                                |
| Hyphen Count                | URL          | g–oo-g-le.com          |                                                                                                                |
| Typosquatted URL            | URL          |                        |                                                                                                                |
| Special Characters          | URL          |                        | “77.75 % of phished URLs are with special characters.”                                                         |
| Unicode                     | URL          |                        |                                                                                                                |
| Fake www                    | URL          | wwwgoogle.com          |                                                                                                                |
| Misspelled URL              | URL          | nesflix.com            |                                                                                                                |

</details>

# AI Phishing Shield

AI Phishing Shield is my cybersecurity project for detecting phishing URLs.

The system checks a URL before the user visits the website. It uses an XGBoost machine learning model together with domain trust and security rules.

The system gives three results:

- **SAFE** - The website opens normally.
- **WARNING** - A warning page is shown and the user can choose whether to continue.
- **DANGEROUS** - The website is blocked.

## Project Objective

The main goal of this project is to help protect users from phishing links.

The system was developed to:

- Check URLs automatically
- Detect suspicious and dangerous links
- Warn users about possible phishing links
- Block high-risk URLs
- Reduce unnecessary blocking of safe websites

## How the System Works

The system follows this process:

```text
User clicks a URL
        ↓
Firefox Extension
        ↓
Local Blacklist Check
        ↓
Flask Backend
        ↓
20 URL Features
        ↓
XGBoost Model
        +
Domain Trust / Security Rules
        ↓
Final Danger Score
        ↓
≤ 20%          SAFE
>20% and <80%  WARNING
≥ 80%          DANGEROUS
```

The Firefox extension gets the URL and sends it to the Flask backend.

The backend extracts 20 features from the URL. The XGBoost model then calculates the risk of the URL.

The system also checks domain trust and some security rules. These results are combined to calculate the final danger score.

## System Screenshots

### Warning Page

When a URL has a medium danger score, the system shows a warning page. The user can return or continue to the website.

![Warning Page](screenshots/warning%20test%20for%20github.png)

### Dangerous URL Blocked

When a URL has a high danger score, the system blocks the website.

![Dangerous URL Blocked](screenshots/danger%20test%20for%20github.png)

### Safe URL

Safe URLs can continue normally without showing a warning or blocked page.

![Safe URL Test](screenshots/safe%20test%20for%20github.png)

## Machine Learning Model

I used XGBoost for phishing URL detection.

The first model was used as the baseline model. It achieved the following results:

| Metric | Result |
|---|---:|
| Accuracy | 93.61% |
| Precision | 89.74% |
| Recall | 94.28% |
| F1-Score | 91.95% |
| Specificity | 93.18% |
| ROC-AUC | 98.47% |
| PR-AUC | 97.79% |
| False Positive Rate | 6.82% |
| False Negative Rate | 5.72% |

After that, I retrained the model using difficult examples that were classified incorrectly.

## Model 2 and Model 3

I compared two retrained models.

| Metric | Model 2 | Model 3 |
|---|---:|---:|
| Accuracy | 97.48% | 97.58% |
| Precision | 99.18% | 98.02% |
| Recall | 96.75% | 98.09% |
| F1-Score | 97.95% | 98.05% |
| FPR | 1.32% | 3.25% |
| FNR | 3.25% | 1.91% |

Model 3 had slightly higher accuracy and recall. However, Model 2 had a lower false positive rate.

I selected **Model 2** for my final system because it gave a better balance between security and normal browser use.

## Final Security Levels

The final system uses these thresholds:

| Danger Score | Result | Action |
|---|---|---|
| ≤ 20% | SAFE | Open website normally |
| > 20% and < 80% | WARNING | Show warning page |
| ≥ 80% | DANGEROUS | Block website |

I added the WARNING level because some URLs are not clearly safe or dangerous. In this case, the system shows the danger score and lets the user decide whether to continue.

## Test Data

For the hybrid system test, I used:

- **325,129 unique safe URLs**
- **533,218 unique dangerous URLs**

I tested different threshold values before choosing the final 20% and 80% thresholds.

## Browser Extension

The Firefox extension checks the URL when the user opens a website.

It communicates with the Flask backend running on the local computer.

The main extension files are:

- `manifest.json` - Extension settings
- `background1.js` - Checks browser navigation and communicates with Flask
- `warning.html` and `warning.js` - Warning page
- `blocked.html` and `blocked.js` - Blocked page

## Technologies Used

- Python
- XGBoost
- Flask
- JavaScript
- HTML
- CSS
- Firefox WebExtension
- Machine Learning

## Project Files

```text
AI-Phishing-Shield/
│
├── app1.py
├── background1.js
├── manifest.json
├── blocked.html
├── blocked.js
├── warning.html
├── warning.js
└── README.md
```

## How to Run

First, start the Flask backend:

```bash
python3 app1.py
```

The Flask server runs at:

```text
http://127.0.0.1:5000
```

Then open Firefox and go to:

```text
about:debugging
```

Choose **This Firefox**, click **Load Temporary Add-on**, and select `manifest.json`.

After loading the extension, URLs can be checked while browsing.

## Limitations

This project is a student cybersecurity project and is still a prototype.

The result depends on the training data, URL features, and security rules. New phishing techniques may not always be detected correctly.

The system also needs the local Flask backend to be running for the machine learning detection to work.

## Future Work

In the future, I would like to:

- Test with newer phishing URLs
- Improve the domain trust checking
- Reduce false positives and false negatives
- Improve the warning system
- Test with more unseen URLs
- Support other browsers
- Improve the user interface

## Author

This project was developed as part of my cybersecurity studies.

It helped me learn more about phishing detection, machine learning, XGBoost, Flask, JavaScript, and Firefox extension development.

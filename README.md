The NVD Assessment Project


A web application designed to assess and report on vulnerabilities in web applications using the National Vulnerability Database (NVD) and various scanning tools.

Overview


The NVD Assessment Project is a comprehensive vulnerability assessment tool that utilizes the NVD database, Wappalyzer, and Nuclei scanning engine to identify and report on potential security vulnerabilities in web applications.

Features


- Vulnerability Scanning: Utilizes Nuclei scanning engine to identify potential vulnerabilities in web applications.
- Technology Detection: Employs Wappalyzer to detect technologies used in web applications.
- NVD Integration: Leverages the NVD database to provide detailed information on identified vulnerabilities.
- Reporting: Generates comprehensive reports on identified vulnerabilities, including severity levels, descriptions, and potential exploits.
- Customizable: Allows users to specify scanning parameters, including URL, technology, and severity level.

Requirements


- Python 3.8+
- Docker
- NVIDIA GPU (optional)
- transformers library
- torch library
- neptune library
- docker library
- paramiko library
- pyelftools library
- pwntools library
- requests library
- beautifulsoup4 library
- python-dotenv library
- argparse library

Installation


1. Clone the repository: git clone https://github.com/your-username/nvd-assessment-project.git
2. Install required packages: pip install -r requirements.txt
3. Build the Docker image: docker build -t nvd-assessment-project .
4. Run the Docker container: docker run -it nvd-assessment-project

Usage


1. Configure the application by modifying the config.json file.
2. Run the application: python app.py
3. Access the web application through your web browser.

API Documentation


API documentation is available at <http://localhost:5000/api/docs>.


License


This project is licensed under the MIT License.

Acknowledgments


- Thanks to the NVD team for providing the vulnerability database.
- Thanks to the Wappalyzer team for providing the technology detection tool.
- Thanks to the Nuclei team for providing the scanning engine.

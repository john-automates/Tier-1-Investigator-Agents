# Cybersecurity Investigation Tool

## Overview

This project is an automated cybersecurity investigation tool designed to analyze potential security incidents. It leverages various OSINT (Open Source Intelligence) techniques and integrates with multiple threat intelligence platforms to provide a comprehensive analysis of suspicious activities.

## Features

- Automated analysis of detection data
- Base64 decoding and analysis of obfuscated scripts
- File hash investigation using VirusTotal
- IP address reputation and geolocation checks
- Advanced web searching and content summarization
- Generation of detailed investigation reports

## Architecture

The tool is built with a modular architecture, consisting of several key components:

1. **Main Orchestrator** (`main.py`): Coordinates the overall investigation process.
2. **Investigation Steps**:
   - `step_1.py`: Initial detection data analysis
   - `step_1_5.py`: Base64 decoding and analysis
   - `step_2.py`: OSINT investigation plan creation
   - `step_3.py`: Execution of the investigation plan
   - `step_4.py`: Report generation
3. **Tools**:
   - File Hash Investigator
   - IP Address Investigator
   - Website Crawler
4. **Agents**:
   - Lead Analyst Agent
   - Threat Intelligence Agent
   - Log Analysis Agent

## Technologies Used

- Python 3.x
- OpenAI GPT-4 for intelligent analysis and report generation
- Google Gemini API for advanced content summarization
- VirusTotal API for file hash analysis
- Shodan API for IP reputation checks
- Custom Search API for web scraping
- Firecrawl for website crawling

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/cybersecurity-investigation-tool.git
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file in the root directory with the following variables:
   ```
   OPENAI_API_KEY=your_openai_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   SHODAN_API_KEY=your_shodan_api_key
   GOOGLE_API_KEY=your_google_api_key
   FIRECRAWL_API_KEY=your_firecrawl_api_key
   GEMINI_API_KEY=your_gemini_api_key
   LEAD_ANALYST_ID=your_lead_analyst_assistant_id
   THREAT_INTEL_ID=your_threat_intel_assistant_id
   LOG_ANALYST_ID=your_log_analyst_assistant_id
   ```

## Usage

1. Prepare a `detection.txt` file with initial incident data in the project root.

2. Run the investigation:
   ```
   python main.py
   ```

3. The tool will generate a `report.txt` file with detailed findings and a `report_overview.md` with a summary of the investigation.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have proper authorization before investigating any systems or networks.


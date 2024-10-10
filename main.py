import logging
import json
from dotenv import load_dotenv
from steps.step_1 import step_1
from steps.step_2 import step_2
from steps.step_3 import step_3

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("investigation.log"),
                        logging.StreamHandler()
                    ])

def write_to_report(step_number: int, step_name: str, data: dict):
    """Write step output to report.txt"""
    with open("report.txt", "a") as report_file:
        report_file.write(f"\n\n--- Step {step_number}: {step_name} ---\n")
        json.dump(data, report_file, indent=2)

def main():
    try:
        # Load environment variables
        load_dotenv()
        logging.info("Environment variables loaded.")
        
        # Clear previous report
        open("report.txt", "w").close()
        logging.info("Previous report cleared.")
        
        # Run step 1
        logging.info("Starting Step 1: Analyzing detection information")
        detection_data = step_1()
        if not detection_data:
            logging.error("Step 1 failed: No detection data obtained")
            return
        write_to_report(1, "Detection Analysis", detection_data)
        logging.info("Step 1 completed successfully")
        
        # Run step 2
        logging.info("Starting Step 2: Creating investigation plan")
        investigation_plan = step_2(detection_data)
        if not investigation_plan:
            logging.error("Step 2 failed: No investigation plan created")
            return
        write_to_report(2, "OSINT Investigation Plan", investigation_plan)
        logging.info("Step 2 completed successfully")
        
        # Run step 3
        logging.info("Starting Step 3: Executing investigation plan")
        investigation_results = step_3(investigation_plan)
        if not investigation_results:
            logging.error("Step 3 failed: No investigation results obtained")
            return
        write_to_report(3, "Investigation Results", investigation_results)
        logging.info("Step 3 completed successfully")
        
        logging.info("All steps completed successfully")
        logging.info("Report generated: report.txt")
    
    except Exception as e:
        logging.error(f"An error occurred during execution: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()
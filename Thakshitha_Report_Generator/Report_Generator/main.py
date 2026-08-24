from report_generator import generate_report
from database import save_report
from mail_response import send_email


def main():

    # -----------------------------------------
    # Temporary Risk Engine output
    # -----------------------------------------

    analysis = {
        "indicator": "http://test-example.com",
        "indicator_type": "URL",
        "risk_score": 85
    }


    # -----------------------------------------
    # Generate final report
    # -----------------------------------------

    report = generate_report(analysis)


    print("\nFinal Security Report")
    print("---------------------")

    for key, value in report.items():
        print(f"{key}: {value}")


    # -----------------------------------------
    # Save report to MySQL
    # -----------------------------------------

    database_result = save_report(report)


    if database_result:

        print(
            "Report successfully stored in MySQL."
        )

    else:

        print(
            "Failed to store report in MySQL."
        )


    # -----------------------------------------
    # Gmail
    # -----------------------------------------

    # TEMPORARY:
    # Use your own Gmail address for testing.
    recipient = "employee@example.com"


    # Don't send until Gmail credentials
    # are configured.

    # email_result = send_email(
    #     report,
    #     recipient
    # )

    # if email_result:
    #     print("Email successfully sent.")
    # else:
    #     print("Email sending failed.")


if __name__ == "__main__":

    main()
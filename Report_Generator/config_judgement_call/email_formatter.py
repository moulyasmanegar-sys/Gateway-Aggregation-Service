def format_risk_email(data):

    # -----------------------------------------
    # EXTRACT DATA SAFELY
    # -----------------------------------------

    risk_analysis = data.get("risk_analysis", {})
    threat = data.get("threat_intelligence", {})
    ioc_analysis = data.get("ioc_analysis", {})

    email_id = data.get("email_id", "N/A")

    risk_score = risk_analysis.get("risk_score", 0)

    classification = risk_analysis.get(
        "classification",
        "UNKNOWN"
    ).upper()

    risk_level = risk_analysis.get(
        "risk_level",
        classification
    )

    total_iocs = threat.get("total_iocs", 0)
    malicious_count = threat.get("malicious_count", 0)
    suspicious_count = threat.get("suspicious_count", 0)
    harmless_count = threat.get("harmless_count", 0)
    undetected_count = threat.get("undetected_count", 0)

    suspicious_keywords = ioc_analysis.get(
        "suspicious_keywords",
        []
    )

    attachments = data.get("attachments", [])

    # -----------------------------------------
    # CLASSIFICATION STYLE
    # -----------------------------------------

    if classification == "MALICIOUS":

        classification_color = "#dc3545"

        classification_text = "MALICIOUS - HIGH RISK"

        classification_message = (
            "This email contains indicators associated "
            "with malicious activity."
        )

    elif classification == "SUSPICIOUS":

        classification_color = "#f0ad4e"

        classification_text = "SUSPICIOUS - MEDIUM RISK"

        classification_message = (
            "This email contains suspicious indicators "
            "and should be reviewed carefully."
        )

    elif classification in ["SAFE", "LOW RISK", "HARMLESS"]:

        classification_color = "#28a745"

        classification_text = "SAFE - LOW RISK"

        classification_message = (
            "No significant malicious indicators were detected."
        )

    else:

        classification_color = "#6c757d"

        classification_text = "UNKNOWN"

        classification_message = (
            "The email classification could not be determined."
        )

    # -----------------------------------------
    # BUILD IOC ANALYSIS ROWS
    # -----------------------------------------

    ioc_rows = ""

    ioc_results = threat.get("ioc_results", [])

    if ioc_results:

        for index, result in enumerate(
            ioc_results,
            start=1
        ):

            ioc_classification = result.get(
                "classification",
                "Unknown"
            )

            ioc_classification_upper = (
                ioc_classification.upper()
            )

            if ioc_classification_upper == "MALICIOUS":

                verdict_color = "#dc3545"

            elif ioc_classification_upper == "SUSPICIOUS":

                verdict_color = "#f0ad4e"

            elif ioc_classification_upper in [
                "HARMLESS",
                "SAFE"
            ]:

                verdict_color = "#28a745"

            else:

                verdict_color = "#6c757d"

            ioc_rows += f"""
            <tr>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                ">
                    {index}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    font-weight: bold;
                ">
                    {result.get("type", "")}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    word-break: break-all;
                ">
                    {result.get("value", "")}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                ">
                    {result.get("malicious", 0)}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                ">
                    {result.get("suspicious", 0)}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                ">
                    {result.get("harmless", 0)}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                ">
                    {result.get("undetected", 0)}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                    text-align: center;
                    font-weight: bold;
                    color: {verdict_color};
                ">
                    {ioc_classification}
                </td>

            </tr>
            """

    else:

        ioc_rows = """
        <tr>

            <td
                colspan="8"
                style="
                    border: 1px solid #e0e0e0;
                    padding: 15px;
                    text-align: center;
                    color: #6b7280;
                "
            >
                No IOC results available.
            </td>

        </tr>
        """

    # -----------------------------------------
    # BUILD SUSPICIOUS KEYWORDS
    # -----------------------------------------

    keyword_html = ""

    if suspicious_keywords:

        for keyword in suspicious_keywords:

            keyword_html += f"""
            <span style="
                display: inline-block;
                background-color: #fff3cd;
                color: #856404;
                border: 1px solid #ffeeba;
                border-radius: 15px;
                padding: 6px 12px;
                margin: 4px;
                font-size: 13px;
            ">
                {keyword}
            </span>
            """

    else:

        keyword_html = """
        <span style="
            color: #6b7280;
            font-size: 13px;
        ">
            No suspicious keywords detected.
        </span>
        """

    # -----------------------------------------
    # BUILD ATTACHMENT LIST
    # -----------------------------------------

    attachment_html = ""

    if attachments:

        for attachment in attachments:

            filename = attachment.get(
                "filename",
                "Unknown Attachment"
            )

            content_type = attachment.get(
                "content_type",
                "Unknown Type"
            )

            attachment_html += f"""
            <tr>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                ">
                    {filename}
                </td>

                <td style="
                    border: 1px solid #e0e0e0;
                    padding: 10px;
                ">
                    {content_type}
                </td>

            </tr>
            """

    else:

        attachment_html = """
        <tr>

            <td
                colspan="2"
                style="
                    border: 1px solid #e0e0e0;
                    padding: 12px;
                    text-align: center;
                    color: #6b7280;
                "
            >
                No attachments found.
            </td>

        </tr>
        """

    # -----------------------------------------
    # BUILD HTML EMAIL
    # -----------------------------------------

    html = f"""
    <!DOCTYPE html>
    <html>

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

    </head>

    <body style="
        margin: 0;
        padding: 0;
        background-color: #f4f6f9;
        font-family: Arial, sans-serif;
    ">

        <div style="
            max-width: 1000px;
            margin: 30px auto;
            background-color: #ffffff;
            border-radius: 12px;
            overflow: hidden;
        ">

            <!-- HEADER -->

            <div style="
                background-color: #1f2937;
                color: white;
                padding: 30px;
                text-align: center;
            ">

                <h1 style="
                    margin: 0;
                    font-size: 26px;
                ">
                    Security Risk Analysis Report
                </h1>

                <p style="
                    margin-top: 10px;
                    margin-bottom: 0;
                    color: #d1d5db;
                ">
                    Automated Email Security & IOC Threat Intelligence Report
                </p>

            </div>

            <!-- CONTENT -->

            <div style="
                padding: 30px;
            ">

                <!-- EMAIL DETAILS -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    Email Details
                </h2>

                <table style="
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 30px;
                ">

                    <tr>

                        <td style="
                            padding: 12px;
                            background-color: #f9fafb;
                            font-weight: bold;
                            width: 30%;
                            border: 1px solid #e5e7eb;
                        ">
                            Email ID
                        </td>

                        <td style="
                            padding: 12px;
                            border: 1px solid #e5e7eb;
                        ">
                            {email_id}
                        </td>

                    </tr>

                </table>

                <!-- RISK SUMMARY -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    Risk Summary
                </h2>

                <div style="
                    background-color: #f9fafb;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                    border-left: 5px solid {classification_color};
                ">

                    <table style="
                        width: 100%;
                        border-collapse: collapse;
                    ">

                        <tr>

                            <td style="
                                padding: 12px;
                                font-weight: bold;
                            ">
                                Risk Score
                            </td>

                            <td style="
                                padding: 12px;
                                font-size: 22px;
                                font-weight: bold;
                            ">
                                {risk_score}/100
                            </td>

                        </tr>

                        <tr>

                            <td style="
                                padding: 12px;
                                font-weight: bold;
                            ">
                                Final Classification
                            </td>

                            <td style="
                                padding: 12px;
                            ">

                                <span style="
                                    background-color: {classification_color};
                                    color: white;
                                    padding: 8px 16px;
                                    border-radius: 20px;
                                    font-weight: bold;
                                ">
                                    {classification_text}
                                </span>

                            </td>

                        </tr>

                        <tr>

                            <td style="
                                padding: 12px;
                                font-weight: bold;
                            ">
                                Risk Level
                            </td>

                            <td style="
                                padding: 12px;
                            ">
                                {risk_level}
                            </td>

                        </tr>

                    </table>

                    <p style="
                        margin-bottom: 0;
                        color: #4b5563;
                    ">
                        {classification_message}
                    </p>

                </div>

                <!-- THREAT INTELLIGENCE SUMMARY -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    Threat Intelligence Summary
                </h2>

                <table style="
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 30px;
                ">

                    <tr>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 12px;
                            text-align: left;
                        ">
                            Metric
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 12px;
                            text-align: center;
                        ">
                            Count
                        </th>

                    </tr>

                    <tr>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                        ">
                            Total IOCs
                        </td>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                            text-align: center;
                            font-weight: bold;
                        ">
                            {total_iocs}
                        </td>

                    </tr>

                    <tr>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                        ">
                            Malicious IOCs
                        </td>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                            text-align: center;
                            font-weight: bold;
                            color: #dc3545;
                        ">
                            {malicious_count}
                        </td>

                    </tr>

                    <tr>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                        ">
                            Suspicious IOCs
                        </td>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                            text-align: center;
                            font-weight: bold;
                            color: #f0ad4e;
                        ">
                            {suspicious_count}
                        </td>

                    </tr>

                    <tr>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                        ">
                            Harmless IOCs
                        </td>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                            text-align: center;
                            font-weight: bold;
                            color: #28a745;
                        ">
                            {harmless_count}
                        </td>

                    </tr>

                    <tr>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                        ">
                            Undetected Results
                        </td>

                        <td style="
                            border: 1px solid #e5e7eb;
                            padding: 12px;
                            text-align: center;
                            font-weight: bold;
                        ">
                            {undetected_count}
                        </td>

                    </tr>

                </table>

                <!-- SUSPICIOUS KEYWORDS -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    Detected Suspicious Keywords
                </h2>

                <div style="
                    margin-bottom: 30px;
                ">
                    {keyword_html}
                </div>

                <!-- ATTACHMENTS -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    Attachments
                </h2>

                <table style="
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 30px;
                ">

                    <tr>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 12px;
                            text-align: left;
                        ">
                            Filename
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 12px;
                            text-align: left;
                        ">
                            Content Type
                        </th>

                    </tr>

                    {attachment_html}

                </table>

                <!-- IOC ANALYSIS -->

                <h2 style="
                    color: #1f2937;
                    border-bottom: 2px solid #e5e7eb;
                    padding-bottom: 10px;
                ">
                    IOC Analysis
                </h2>

                <table style="
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 12px;
                    margin-bottom: 30px;
                ">

                    <tr>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            #
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Type
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            IOC Value
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Malicious
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Suspicious
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Harmless
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Undetected
                        </th>

                        <th style="
                            background-color: #1f2937;
                            color: white;
                            padding: 8px;
                        ">
                            Classification
                        </th>

                    </tr>

                    {ioc_rows}

                </table>

                <!-- FINAL VERDICT -->

                <div style="
                    background-color: #f9fafb;
                    border-left: 6px solid {classification_color};
                    padding: 25px;
                    border-radius: 6px;
                    text-align: center;
                ">

                    <h2 style="
                        margin-top: 0;
                        color: #1f2937;
                    ">
                        Final Security Verdict
                    </h2>

                    <div style="
                        font-size: 26px;
                        font-weight: bold;
                        color: {classification_color};
                    ">
                        {classification}
                    </div>

                    <p style="
                        margin-bottom: 0;
                        color: #4b5563;
                    ">
                        Final Risk Score:
                        <strong>{risk_score}/100</strong>
                    </p>

                </div>

                <!-- FOOTER -->

                <p style="
                    margin-top: 35px;
                    text-align: center;
                    color: #6b7280;
                    font-size: 12px;
                ">
                    This report was automatically generated by the
                    Security Risk Engine.
                    <br><br>
                    Automated Email → IOC Extraction → Threat Analysis →
                    Risk Classification → TLP Classification
                </p>

            </div>

        </div>

    </body>

    </html>
    """

    return html
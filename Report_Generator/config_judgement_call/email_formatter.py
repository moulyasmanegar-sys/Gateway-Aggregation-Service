def format_risk_email(data):

    risk_analysis = data["risk_analysis"]
    threat = data["threat_intelligence"]

    risk_score = risk_analysis["risk_score"]
    classification = risk_analysis["classification"]

    url_rows = ""

    for result in threat["url_results"]:
        url_rows += f"""
        <tr>
            <td>{result["url"]}</td>
            <td>{result["malicious"]}</td>
            <td>{result["suspicious"]}</td>
            <td>{result["harmless"]}</td>
            <td>{result["undetected"]}</td>
        </tr>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
    </head>

    <body style="
        font-family: Arial, sans-serif;
        background-color: #f4f6f8;
        padding: 20px;
        margin: 0;
    ">

        <div style="
            max-width: 700px;
            margin: auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
        ">

            <h2 style="
                margin-top: 0;
                text-align: center;
            ">
                Security Risk Analysis Report
            </h2>

            <hr>

            <!-- Email Details -->

            <p>
                <strong>Email ID:</strong>
                {data["email_id"]}
            </p>

            <!-- Risk Summary -->

            <h3>Risk Summary</h3>

            <table
                cellpadding="10"
                cellspacing="0"
                style="width: 100%; border-collapse: collapse;"
            >
                <tr>
                    <td style="border: 1px solid #ddd;">
                        <strong>Risk Score</strong>
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {risk_score}/100
                    </td>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        <strong>Classification</strong>
                    </td>

                    <td style="border: 1px solid #ddd;">
                        <strong>{classification}</strong>
                    </td>
                </tr>
            </table>

            <!-- Threat Intelligence -->

            <h3>Threat Intelligence</h3>

            <table
                cellpadding="8"
                cellspacing="0"
                style="
                    width: 100%;
                    border-collapse: collapse;
                "
            >

                <tr>
                    <th style="border: 1px solid #ddd;">
                        Metric
                    </th>

                    <th style="border: 1px solid #ddd;">
                        Count
                    </th>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        Total URLs
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {threat["total_urls"]}
                    </td>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        Malicious
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {threat["malicious_count"]}
                    </td>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        Suspicious
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {threat["suspicious_count"]}
                    </td>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        Harmless
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {threat["harmless_count"]}
                    </td>
                </tr>

                <tr>
                    <td style="border: 1px solid #ddd;">
                        Undetected
                    </td>

                    <td style="border: 1px solid #ddd;">
                        {threat["undetected_count"]}
                    </td>
                </tr>

            </table>

            <!-- URL Analysis -->

            <h3>URL Analysis</h3>

            <table
                cellpadding="8"
                cellspacing="0"
                style="
                    width: 100%;
                    border-collapse: collapse;
                    font-size: 14px;
                "
            >

                <tr>
                    <th style="border: 1px solid #ddd;">
                        URL
                    </th>

                    <th style="border: 1px solid #ddd;">
                        Malicious
                    </th>

                    <th style="border: 1px solid #ddd;">
                        Suspicious
                    </th>

                    <th style="border: 1px solid #ddd;">
                        Harmless
                    </th>

                    <th style="border: 1px solid #ddd;">
                        Undetected
                    </th>
                </tr>

                {url_rows}

            </table>

            <!-- Final Classification -->

            <h3>Final Classification</h3>

            <div style="
                padding: 15px;
                border: 1px solid #ddd;
                border-radius: 6px;
                text-align: center;
            ">

                <strong style="font-size: 20px;">
                    {classification}
                </strong>

                <p style="margin-bottom: 0;">
                    Risk Score: {risk_score}/100
                </p>

            </div>

            <br>

            <p style="
                font-size: 13px;
                color: #666;
            ">
                This report was automatically generated by the
                Security Risk Engine.
            </p>

        </div>

    </body>
    </html>
    """

    return html
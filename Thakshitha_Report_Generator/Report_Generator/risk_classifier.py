def classify_risk(risk_score):

    if risk_score < 0 or risk_score > 100:
        raise ValueError("Risk score must be between 0 and 100")

    if risk_score <= 29:
        return "LOW"

    elif risk_score <= 69:
        return "MEDIUM"

    else:
        return "HIGH"
    
if __name__ == "__main__":

    print(classify_risk(20))
    print(classify_risk(55))
    print(classify_risk(85))
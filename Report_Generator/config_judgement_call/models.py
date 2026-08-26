from django.db import models


class Report(models.Model):
    email_id = models.IntegerField()
    indicator = models.CharField(max_length=2048, null=True, blank=True)
    indicator_type = models.CharField(max_length=50, null=True, blank=True)

    risk_score = models.DecimalField(max_digits=5, decimal_places=2)
    risk_level = models.CharField(max_length=20, null=True, blank=True)
    classification = models.CharField(max_length=20, null=True, blank=True)

    verdict = models.CharField(max_length=50, null=True, blank=True)
    action = models.CharField(max_length=50, null=True, blank=True)
    recommendation = models.TextField(null=True, blank=True)

    total_urls = models.IntegerField(default=0)
    malicious_count = models.IntegerField(default=0)
    suspicious_count = models.IntegerField(default=0)
    harmless_count = models.IntegerField(default=0)
    undetected_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "reports"
        managed = False


class URLResult(models.Model):
    report = models.ForeignKey(
        Report,
        on_delete=models.CASCADE,
        related_name="url_results",
        db_column="report_id"
    )

    url = models.CharField(max_length=2048)
    malicious = models.IntegerField(default=0)
    suspicious = models.IntegerField(default=0)
    harmless = models.IntegerField(default=0)
    undetected = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "url_results"
        managed = False
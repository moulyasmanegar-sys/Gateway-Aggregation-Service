from django.db import models

class Email(models.Model):
    sender = models.EmailField()
    receiver = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    urls = models.JSONField(default=list)
    timestamp = models.DateTimeField(auto_now_add=True)
    attachment = models.CharField(max_length=255, blank=True)

    def __str__(self):
        return self.subject
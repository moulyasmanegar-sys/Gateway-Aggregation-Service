from rest_framework import serializers


# ============================================================
# ATTACHMENT SERIALIZER
# ============================================================

class AttachmentSerializer(serializers.Serializer):

    filename = serializers.CharField()

    filepath = serializers.CharField()

    content_type = serializers.CharField()


# ============================================================
# EMAIL DATA SERIALIZER
# ============================================================

class EmailDataSerializer(serializers.Serializer):

    id = serializers.IntegerField(
        required=False
    )

    sender = serializers.EmailField()

    receiver = serializers.EmailField()

    subject = serializers.CharField()

    body = serializers.CharField()

    urls = serializers.ListField(
        child=serializers.URLField(),
        required=False,
        default=list,
    )

    timestamp = serializers.DateTimeField(
        required=False
    )

    attachments = AttachmentSerializer(
        many=True,
        required=False,
        default=list,
    )


# ============================================================
# RISK INPUT SERIALIZER
# ============================================================

class RiskInputSerializer(serializers.Serializer):

    message = serializers.CharField(
        required=False,
        allow_blank=True,
    )

    email_id = serializers.IntegerField()

    urls = serializers.ListField(
        child=serializers.URLField(),
        required=False,
        default=list,
    )

    attachments = AttachmentSerializer(
        many=True,
        required=False,
        default=list,
    )

    data = EmailDataSerializer()
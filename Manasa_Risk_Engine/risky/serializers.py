from rest_framework import serializers


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

    attachment = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
    )


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

    data = EmailDataSerializer()
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ecp_auth", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="ecpcertificate",
            name="taxpayer_id",
            field=models.CharField(max_length=10, unique=True),
        ),
    ]

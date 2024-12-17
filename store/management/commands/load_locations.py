import csv
from django.core.management.base import BaseCommand
from store.models import Country, State, LocalGovernment, ShippingFee  # Replace 'myapp' with your app name

class Command(BaseCommand):
    help = 'Load locations and shipping fees from a CSV file'

    def handle(self, *args, **kwargs):
        file_path = r'C:\Users\hp\Olaz ecommerce project\ecommerce\store\data\location.csv'  # Path to your CSV file

        with open(file_path, mode='r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                # Get or create country
                country, _ = Country.objects.get_or_create(name=row['country'])

                # Get or create state
                state, _ = State.objects.get_or_create(name=row['state'], country=country)

                # Get or create LGA
                lga, _ = LocalGovernment.objects.get_or_create(name=row['lga'], state=state)

                shipping_fee, created = ShippingFee.objects.get_or_create(lga=lga, defaults={'fee': row['shipping_fee']})

                if not created:
                    shipping_fee.fee = row['shipping_fee']
                    shipping_fee.save()

                # Use the instance to display the shipping fee
                self.stdout.write(f"Added/Updated {lga.name} with shipping fee {shipping_fee.fee}")
                

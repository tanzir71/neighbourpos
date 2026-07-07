# NeighbourPOS Export Guide

NeighbourPOS records customers, orders, campaign queues, and payment status. It does not send SMS/email/WhatsApp messages and it does not process payments. The export profiles below are designed so a shop owner can download a CSV, import it into the sending tool they already use, and keep the source data on their own hosting.

By default, campaign and customer exports include only opted-in contacts. If a staff user enables an opt-in override, NeighbourPOS audits that override. Consent, quiet hours, sender registration, unsubscribe handling, and local law remain the merchant's responsibility.

## Common Rules

- File type: UTF-8 CSV. Use the Excel-friendly option if the file will be opened in Excel before importing.
- Phone format: NeighbourPOS attempts to normalize phones to E.164, such as `+15550100001`, using the store default country code.
- Message fields: campaign exports render `{name}`, `{first_name}`, `{coupon_code}`, and `{store_name}` before writing CSV rows. Debtor reminder exports also render `{balance}`.
- Deduping: profiles dedupe on the identifier the destination expects, such as email for Mailchimp and phone for SMS/WhatsApp.
- Safety: CSV cells are escaped to reduce spreadsheet formula injection risk.

## Mailchimp

Use this when you want an email-focused audience import with tags for segmentation.

Header:

```csv
Email Address,First Name,Last Name,Phone,Tags
```

Example:

```csv
Email Address,First Name,Last Name,Phone,Tags
maya@example.com,Maya,Rahman,+15550100001,"campaign:July winback,vip"
omar@example.com,Omar,Ali,+15550100002,"campaign:July winback,nearby"
lina@example.com,Lina,Chen,+15550100003,"campaign:July winback"
```

Import path:

1. In NeighbourPOS, open `Campaigns`, queue recipients, choose `Mailchimp`, then download the CSV.
2. In Mailchimp, open `Audience`, choose the audience, select `Add contacts`, then `Import contacts`.
3. Choose `Upload a file`, upload the CSV, and map `Email Address`, `First Name`, `Last Name`, `Phone`, and `Tags`.
4. Review tags before completing the import so the campaign tag stays attached to the imported contacts.

Reference: [Mailchimp import contacts](https://mailchimp.com/help/import-contacts-mailchimp/) and [Mailchimp import file formatting](https://mailchimp.com/help/format-guidelines-for-your-import-file/).

## Brevo

Use this when you want one file that can identify contacts by email or SMS number and carry the coupon code as an attribute.

Header:

```csv
EMAIL,SMS,FIRSTNAME,LASTNAME,COUPON_CODE
```

Example:

```csv
EMAIL,SMS,FIRSTNAME,LASTNAME,COUPON_CODE
maya@example.com,+15550100001,Maya,Rahman,JULY-MAYA
,+15550100002,Omar,Ali,JULY-OMAR
lina@example.com,+15550100003,Lina,Chen,JULY-LINA
```

Import path:

1. In NeighbourPOS, open `Campaigns`, queue recipients, choose `Brevo`, then download the CSV.
2. In Brevo, go to `CRM > Contacts`, click `Import contacts`, keep `Contacts` selected, and choose `Upload a file`.
3. Upload the CSV and confirm the file preview.
4. Map columns to Brevo attributes: `EMAIL` to email, `SMS` to SMS, `FIRSTNAME` to first name, `LASTNAME` to last name, and `COUPON_CODE` as an existing or new attribute.
5. Select the destination list and finish the import.

Reference: [Brevo import contacts](https://help.brevo.com/hc/en-us/articles/115000719584-Import-your-contacts-to-Brevo) and [Brevo import file requirements](https://help.brevo.com/hc/en-us/articles/208729849-Create-a-file-to-import-your-contacts).

## SMS Tools

Use this for SMS platforms that accept contact CSV imports, including SimpleTexting and TextMagic. Rows without a valid normalized phone are excluded.

Header:

```csv
phone,name,coupon_code,message
```

Example:

```csv
phone,name,coupon_code,message
+15550100001,Maya Rahman,JULY-MAYA,"Hi Maya, show JULY-MAYA for a thank-you discount."
+15550100002,Omar Ali,JULY-OMAR,"Hi Omar, show JULY-OMAR for a thank-you discount."
+15550100003,Lina Chen,JULY-LINA,"Hi Lina, show JULY-LINA for a thank-you discount."
```

SimpleTexting import path:

1. In NeighbourPOS, open `Campaigns`, queue recipients, choose `SMS`, then download the CSV.
2. In SimpleTexting, open `Contacts`, create or choose a list, and click `Add contacts`.
3. Upload the CSV or drag it into the import area.
4. Map `phone`, `name`, `coupon_code`, and `message` as contact fields or custom fields.
5. Confirm the contacts are consenting contacts, then finish the import.

TextMagic import path:

1. In NeighbourPOS, open `Campaigns`, queue recipients, choose `SMS`, then download the CSV.
2. In TextMagic, open `Contacts`, click `Import`, and upload the CSV.
3. Match the CSV columns to TextMagic contact fields and dynamic fields.
4. If prompted, choose the correct country only for numbers that do not already include a country code.
5. Select the destination list and start the import.

References: [SimpleTexting contact import](https://simpletexting.com/features/import-contacts/) and [TextMagic CSV import](https://support.textmagic.com/article/import-contacts/).

## WhatsApp Manual Workflow

Use this when the shop sends one-by-one from a spreadsheet. The `wa_link` opens a WhatsApp chat with the rendered message prefilled; the merchant still reviews and sends each message manually.

Header:

```csv
phone,name,message,wa_link
```

Example:

```csv
phone,name,message,wa_link
+15550100001,Maya Rahman,"Hi Maya, show JULY-MAYA for a thank-you discount.",https://wa.me/15550100001?text=Hi%20Maya%2C%20show%20JULY-MAYA%20for%20a%20thank-you%20discount.
+15550100002,Omar Ali,"Hi Omar, show JULY-OMAR for a thank-you discount.",https://wa.me/15550100002?text=Hi%20Omar%2C%20show%20JULY-OMAR%20for%20a%20thank-you%20discount.
+15550100003,Lina Chen,"Hi Lina, show JULY-LINA for a thank-you discount.",https://wa.me/15550100003?text=Hi%20Lina%2C%20show%20JULY-LINA%20for%20a%20thank-you%20discount.
```

Workflow:

1. In NeighbourPOS, open `Campaigns`, queue recipients, choose `WhatsApp`, then download the CSV.
2. Open the CSV in a spreadsheet and check each row.
3. Click a `wa_link`; WhatsApp opens a chat to the phone number with the message prefilled.
4. Review the message, make any edits needed, and send manually.
5. Keep the sent/not-sent status in your spreadsheet if you need a manual sending log.

Reference: [WhatsApp click to chat](https://faq.whatsapp.com/5913398998672934).

## Customer Exports

The CRM `Export customers` panel uses the same profiles without requiring a campaign. Use it for a clean opted-in phone book, a saved segment, or a provider-ready backup of customers you are allowed to contact.

The same consent rule applies: opted-in contacts only by default; overrides are audited; compliance remains the merchant's responsibility.

For customer credit tabs, use the CRM `Debtor reminders` export. It downloads an SMS-profile CSV for customers with an outstanding balance and renders `{balance}` in currency units, for example `Hi Maya, you owe $24.00.`

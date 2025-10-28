too many email. but the ui only let's you delete 50 at a time. So we're going to sort by sender and delete in bulk by largest sender. For like the top 10, which gives us like 12k messages back.

```bash
source .venv/bin/activate
pip3 install -r requirements.txt
python3
```

then:
```python
from gmailer import Gmailer

client = Gmailer()
```
~~ ~~ ~~

Then you can perform operations like:
```python
>> client.get_messages(maxResults=10,includeSpamTrash=False)

```
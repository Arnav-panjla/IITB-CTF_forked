# 

1. Download the database "https://tlctf2025-hibc.chals.io//download_db?api_key=..." named as "runtime_db.csv" using ADMIN_API_KEY

2. extract.py for extracting emails to emails.txt
![alt text](image-2.png)

3. Now brute force email to the endpoint for gathering breach data and store it to responses.txt
![alt text](image-3.png)

4. Search for "pwned": true
![alt text](image-4.png)

5. Now we got the breached email and admin -> blake.baker20@acme.test

6. Here is the flag value given in server.py
![alt text](image-5.png)

7. Here we can see we need to compute HMAC-SHA256 of the admin email using FLAG_SECRET
![alt text](image-6.png)

8. Build Flag
- HMAC-SHA256 = aefefb18de559dc272e7789ba617064886b1f953d953d6e963070ce7dd3bcda1

- The token builds flag as trustctf{<first 12 chars of HMAC>} ->
trustctf{aefefb18de55}
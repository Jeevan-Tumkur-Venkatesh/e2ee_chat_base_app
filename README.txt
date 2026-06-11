# Install required packages
pip3 install -r requirements.txt

# Start encrypted chat server
python3 chat.py server 127.0.0.1 5000 --ttl 60 --session-ttl 120

# Start encrypted chat client (in another terminal)
python3 chat.py client 127.0.0.1 5000 --ttl 60 --session-ttl 120

# Run crypto tests and performance evaluation
python3 tests.py     # encryption correctness
python3 performance_test.py   # speed benchmarking


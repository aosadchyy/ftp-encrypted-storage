# set base image (host OS)
# docker run -d -p 9921:9921 -v /data/ftp_data:/ftp_data lockerua/ftp-encrypted-storage
FROM python:3.6

# set the working directory in the container
WORKDIR /

# copy the dependencies file to the working directory
COPY requirements.txt .

# install dependencies
RUN pip install -r requirements.txt

# copy the the local src  to the working directory
COPY ftpserveraes.py .

USER 1000

# command to run on container start
CMD [ "python", "/ftpserveraes.py", "alex", "/ftp_data" ]
FROM centos:centos7
LABEL maintainer="Rainer Hörbe <r2h2@hoerbe.at>" \
      version="0.0.0" \
      #UID_TYPE: select one of root, non-root or random to announce container behavior wrt USER
      UID_TYPE="random" \
      #didi_dir="https://raw.githubusercontent.com/identinetics/dscripts-test/master/didi" \
      capabilities='--cap-drop=all'

ARG UID=343006
ARG USERNAME=ldap
ENV GID 0
RUN useradd --gid $GID --uid $UID ldap \
 && chown $UID:$GID /run

RUN yum -y update \
 && yum -y install epel-release \
 && yum -y install curl iproute lsof net-tools \
 && yum -y install python34-devel bzip2 \
 && curl https://bootstrap.pypa.io/get-pip.py | python3.4 \
 && pip3 install ldap3 \
 && yum clean all

COPY py-dump-ph/requirements.txt /tmp/
RUN pip3 install -r /tmp/requirements.txt
RUN rm /tmp/requirements.txt

RUN mkdir -p /opt/bin
COPY py-dump-ph /opt/bin
COPY startup.py /bin/startup
RUN chmod a+x /bin/startup
RUN chmod a+x /opt/bin/*.py

VOLUME /var/data

COPY secret/dump.conf /var/data/dump.conf
copy secret/certificates.pem /var/data

#ENTRYPOINT [ "/bin/startup" ]
CMD [ "/bin/startup" ]


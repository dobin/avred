FROM archlinux/base
RUN echo "root:root" | chpasswd
RUN useradd -m -G wheel -s /bin/bash toto \
	&& echo "toto:toto" | chpasswd
RUN pacman -Syu --noconfirm && pacman -Sy --noconfirm git sudo vim base-devel cabextract python3 cmake lib32-glibc lib32-gcc-libs gcc-multilib python-pip radare2
RUN echo -e "%wheel ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/99_wheel
RUN python3 -m pip install tqdm r2pipe

#RUN cd /tmp \
#	&& git clone https://aur.archlinux.org/yay.git \
#	&& cd yay \
#	&& chown -R toto. /tmp/yay/ \
#	&& sudo -u toto makepkg -s \
#	&& pacman --noconfirm -U /tmp/yay/yay*.pkg.tar.xz
#
#RUN sudo -u toto yay -Sy --noconfirm cmake

USER toto
WORKDIR /home/toto

#RUN git clone https://github.com/taviso/loadlibrary# && cd loadlibrary && make
#COPY engine/* /home/toto/loadlibrary/engine

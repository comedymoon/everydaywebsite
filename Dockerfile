FROM php:8.2-apache

# Enable modules: rewrite, headers, remoteip
RUN a2enmod rewrite headers remoteip

# Copy code
COPY . /var/www/html/

# Ensure storage exists with empty files
RUN mkdir -p /var/www/html/storage &&     touch /var/www/html/storage/banned.txt &&     touch /var/www/html/storage/whitelist.txt &&     touch /var/www/html/storage/visits.log &&     touch /var/www/html/storage/debug.log &&     chown -R www-data:www-data /var/www/html/storage &&     chmod 600 /var/www/html/storage/*

# Set document root to /public
RUN sed -ri 's#DocumentRoot /var/www/html#DocumentRoot /var/www/html/public#' /etc/apache2/sites-available/000-default.conf  && sed -ri 's#<Directory /var/www/>#<Directory /var/www/html/public/>#' /etc/apache2/apache2.conf  && sed -ri 's#<Directory /var/www/html/>#<Directory /var/www/html/public/>#' /etc/apache2/apache2.conf

# Security: proper ownership and permissions
RUN chown -R www-data:www-data /var/www/html &&     find /var/www/html -type d -exec chmod 755 {} \; &&     find /var/www/html -type f -exec chmod 644 {} \; &&     chmod 700 /var/www/html/storage

# RemoteIP config for Cloudflare (trust CF-Connecting-IP)
COPY apache-remoteip.conf /etc/apache2/conf-available/remoteip.conf
RUN a2enconf remoteip

# Entrypoint tweaks for Render port
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PORT=10000
CMD ["/entrypoint.sh"]

FROM php:8.2-apache

RUN docker-php-ext-install mysqli && a2enmod rewrite

COPY . /var/www/html/
RUN chmod -R 777 /var/www/html

# Add entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]

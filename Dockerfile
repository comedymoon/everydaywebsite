# Базовый PHP + Apache
FROM php:8.2-apache

# Включаем нужные модули
RUN docker-php-ext-install mysqli && a2enmod rewrite

# Копируем файлы сайта в контейнер
COPY . /var/www/html/

# Даем права на запись (для логов/бан-листа)
RUN chmod -R 777 /var/www/html

# Apache слушает порт 80
EXPOSE 80

CMD ["apache2-foreground"]

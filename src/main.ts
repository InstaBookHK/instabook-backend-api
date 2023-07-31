import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { GlobalExceptionFilter } from './filters/global-exception.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);

  app.setGlobalPrefix('api');
  app.enableCors({
    origin: configService.get<string>('CORS_ORIGIN')?.split(',') ?? [],
  });
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
    }),
  );
  app.useGlobalFilters(new GlobalExceptionFilter()); // globally catch exceptions

  const config = new DocumentBuilder()
    .setTitle(process.env.SWAGGER_TITLE ?? '')
    .setDescription(process.env.SWAGGER_DESCRIPTION ?? '')
    .setVersion(process.env.SWAGGER_VERSION ?? '')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('swagger', app, document);

  await app.listen(process.env.PORT || 3000);
}
bootstrap();

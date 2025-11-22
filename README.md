# MailSafePro Email Validation Widget (Premium)

El estándar de la industria para la validación de correos electrónicos en el frontend. Convierte más usuarios con una experiencia de validación fluida, inteligente y hermosa.

## ✨ Características Premium

- **🎨 UI de Clase Mundial**: Iconos flotantes animados, micro-interacciones y diseño "Glassmorphism".
- **🧠 Inteligencia Artificial**: Detecta errores tipográficos (`gmil.com` -> `gmail.com`) y sugiere correcciones en un clic.
- **⚡ Performance**: Debounce inteligente y animaciones optimizadas (60fps).
- **♿ Accesibilidad**: Soporte completo para lectores de pantalla (ARIA).
- **🛠️ Developer Friendly**: Arquitectura orientada a objetos y definiciones TypeScript.

## 🚀 Instalación Rápida

Agrega el script y configura tu API Key. El widget se inicializa automáticamente.

```html
<script 
    src="https://cdn.mailsafepro.com/widget.js" 
    data-api-key="TU_API_KEY" 
    data-input-id="email-input"
></script>

<input type="email" id="email-input" placeholder="tu@email.com">
```

## ⚙️ Configuración Avanzada

Puedes configurar el widget mediante atributos `data-` en la etiqueta `<script>` o instanciándolo manualmente.

### Vía Atributos HTML

| Atributo | Descripción | Default |
|----------|-------------|---------|
| `data-api-key` | Tu clave de API. | - |
| `data-input-id` | ID del input a validar. | - |
| `data-check-smtp` | Activa verificación SMTP profunda. | `false` |
| `data-debounce` | Tiempo de espera (ms) al escribir. | `600` |
| `data-base-url` | URL base de la API (opcional). | `https://email-validation-api-jlra.onrender.com` |

### Vía JavaScript (Para SPAs / React / Vue)

```javascript
// Asegúrate de cargar el script primero
const input = document.getElementById('mi-input');

const widget = new MailSafeProWidget(input, {
    apiKey: 'TU_API_KEY',
    checkSmtp: true,
    showIcons: true,
    messages: {
        valid: '¡Se ve bien!',
        invalid: 'Correo no válido',
        suggestion: '¿Quizás quisiste decir {suggestion}?'
    }
});
```

## 📦 Despliegue a Producción

1.  **Hosting del Script**: Sube el archivo `mailsafepro-widget.js` a tu CDN o servidor estático (ej: AWS S3, Cloudflare R2, o la carpeta `public` de tu servidor web).
2.  **CORS en Backend**: Asegúrate de que tu API permita peticiones desde el dominio donde alojarás el widget.
    -   Si usas FastAPI, asegúrate de tener configurado `CORSMiddleware` con `allow_origins=["*"]` (o tu dominio específico).
3.  **API Key**: Utiliza una API Key válida en producción.
    -   *Nota*: La clave `DEMO_KEY_123` activa el "Modo Demo" para pruebas locales sin backend.

## 🎨 Personalización CSS

El widget inyecta estilos modernos por defecto, pero puedes sobrescribirlos fácilmente.

```css
/* Cambiar color de éxito */
.msp-input-valid {
    border-color: #00C853 !important;
}

/* Personalizar el chip de sugerencia */
.msp-suggestion {
    background-color: #F3E5F5;
    color: #7B1FA2;
}
```

## 📦 TypeScript Support

Incluimos un archivo de definiciones `index.d.ts` para autocompletado en VS Code.

```typescript
import { MailSafeProWidget } from 'mailsafepro-widget';
```

---
© 2025 MailSafePro. All rights reserved.

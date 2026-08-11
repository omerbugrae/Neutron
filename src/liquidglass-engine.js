/*
 * Neutron LiquidGlass Engine
 *
 * Dependency-free WebGL2 compositor for Electron/Chromium.
 * The engine renders both the procedural Neutron wallpaper and every DOM
 * element marked with [data-liquidglass] in one shared optical field. This is
 * important: each surface samples the same background, so refraction remains
 * coherent when cards, navigation, and controls sit next to one another.
 */

(function bootstrapNeutronLiquidGlass(global) {
  'use strict';

  const ENGINE_NAME = 'Neutron LiquidGlass';
  const ENGINE_VERSION = '0.4.0';
  const CANVAS_ID = 'liquidglass-canvas';
  const STYLE_ID = 'liquidglass-runtime-style';
  const SURFACE_SELECTOR = '[data-liquidglass]';
  const ROOT_SELECTOR = '.antivirus-window';
  const MAX_SURFACES = 16;
  const TWO_PI = Math.PI * 2;

  const BODY_CLASSES = Object.freeze({
    ready: 'liquidglass-webgl',
    fallback: 'liquidglass-fallback',
    webgl1: 'liquidglass-webgl1-available',
    paused: 'liquidglass-paused',
    reducedMotion: 'liquidglass-reduced-motion',
    contextLost: 'liquidglass-context-lost',
    debug: 'liquidglass-debug',
  });

  const DEFAULT_OPTIONS = Object.freeze({
    rootSelector: ROOT_SELECTOR,
    surfaceSelector: SURFACE_SELECTOR,
    maxSurfaces: MAX_SURFACES,
    maxDevicePixelRatio: 1.35,
    minResolutionScale: 0.56,
    maxResolutionScale: 0.86,
    resolutionScale: 0.78,
    targetFrameRate: 45,
    idleFrameRate: 2,
    idleDelay: 600,
    maxFrameDelta: 0.05,
    reducedMotion: 'system',
    autoQuality: true,
    quality: 0,
    debug: false,
    pointerInfluence: 1,
    pointerSmoothing: 0.14,
    pointerVelocityDecay: 0.86,
    ambientSpeed: 1,
    refractionScale: 1,
    dispersionScale: 1,
    specularScale: 1,
    causticsScale: 1,
    frostScale: 1,
    windowCornerRadius: 0,
    windowDepth: 1.18,
    windowRefraction: 1,
    windowDispersion: 0.88,
    windowSpecular: 1.12,
    windowCaustics: 1,
    surfaceMeasureInterval: 120,
    rootBackgroundAlpha: 1,
    pauseWhenHidden: true,
    palette: Object.freeze({
      midnight: Object.freeze([0.018, 0.035, 0.12]),
      navy: Object.freeze([0.02, 0.16, 0.46]),
      cobalt: Object.freeze([0.055, 0.25, 0.94]),
      violet: Object.freeze([0.42, 0.14, 0.96]),
      cyan: Object.freeze([0.04, 0.69, 0.93]),
      mint: Object.freeze([0.16, 0.94, 0.71]),
    }),
  });

  const ATTRIBUTE_NAMES = Object.freeze([
    'data-liquidglass',
    'data-glass-radius',
    'data-glass-depth',
    'data-glass-refraction',
    'data-glass-dispersion',
    'data-glass-frost',
    'data-glass-specular',
    'data-glass-interactive',
    'data-glass-tint',
    'data-glass-opacity',
    'data-glass-disabled',
    'data-glass-id',
  ]);

  const VERTEX_SHADER_SOURCE = `#version 300 es
    precision highp float;

    const vec2 POSITIONS[3] = vec2[3](
      vec2(-1.0, -1.0),
      vec2( 3.0, -1.0),
      vec2(-1.0,  3.0)
    );

    out vec2 vUv;

    void main() {
      vec2 position = POSITIONS[gl_VertexID];
      vUv = position * 0.5 + 0.5;
      gl_Position = vec4(position, 0.0, 1.0);
    }
  `;

  const FRAGMENT_SHADER_SOURCE = `#version 300 es
    precision highp float;
    precision highp int;

    #define MAX_SURFACES ${MAX_SURFACES}

    in vec2 vUv;
    out vec4 outColor;

    uniform vec2 uResolution;
    uniform vec2 uCssResolution;
    uniform float uMotionTime;
    uniform vec4 uPointer;
    uniform vec4 uPointerMotion;
    uniform int uSurfaceCount;
    uniform int uQuality;
    uniform int uDebug;
    uniform float uAmbientSpeed;
    uniform float uRefractionScale;
    uniform float uDispersionScale;
    uniform float uSpecularScale;
    uniform float uCausticsScale;
    uniform float uFrostScale;
    uniform float uRootBackgroundAlpha;
    uniform vec4 uWindowOptics;
    uniform vec4 uWindowMaterial;
    uniform vec3 uPalette[6];

    // rect = center.x, center.y, halfWidth, halfHeight in CSS pixels.
    uniform vec4 uSurfaceRects[MAX_SURFACES];

    // optics = radius, depth, refraction, dispersion.
    uniform vec4 uSurfaceOptics[MAX_SURFACES];

    // material = frost, specular, interactive, opacity.
    uniform vec4 uSurfaceMaterial[MAX_SURFACES];

    // tint = linear-ish RGB and tint amount.
    uniform vec4 uSurfaceTint[MAX_SURFACES];

    const float PI = 3.1415926535897932384626433832795;
    const float TAU = 6.283185307179586476925286766559;
    const float EPSILON = 0.00001;

    float saturate(float value) {
      return clamp(value, 0.0, 1.0);
    }

    vec2 saturate(vec2 value) {
      return clamp(value, vec2(0.0), vec2(1.0));
    }

    vec3 saturate(vec3 value) {
      return clamp(value, vec3(0.0), vec3(1.0));
    }

    float safeLength(vec2 value) {
      return max(length(value), EPSILON);
    }

    vec2 safeNormalize(vec2 value) {
      return value / safeLength(value);
    }

    vec3 safeNormalize(vec3 value) {
      return value / max(length(value), EPSILON);
    }

    float hash11(float value) {
      value = fract(value * 0.1031);
      value *= value + 33.33;
      value *= value + value;
      return fract(value);
    }

    float hash21(vec2 point) {
      vec3 p3 = fract(vec3(point.xyx) * 0.1031);
      p3 += dot(p3, p3.yzx + 33.33);
      return fract((p3.x + p3.y) * p3.z);
    }

    vec2 hash22(vec2 point) {
      vec3 p3 = fract(vec3(point.xyx) * vec3(0.1031, 0.1030, 0.0973));
      p3 += dot(p3, p3.yzx + 33.33);
      return fract((p3.xx + p3.yz) * p3.zy);
    }

    float valueNoise(vec2 point) {
      vec2 cell = floor(point);
      vec2 fraction = fract(point);
      vec2 curve = fraction * fraction * (3.0 - 2.0 * fraction);

      float a = hash21(cell);
      float b = hash21(cell + vec2(1.0, 0.0));
      float c = hash21(cell + vec2(0.0, 1.0));
      float d = hash21(cell + vec2(1.0, 1.0));

      return mix(
        mix(a, b, curve.x),
        mix(c, d, curve.x),
        curve.y
      );
    }

    float signedRoundedBox(
      vec2 point,
      vec2 halfSize,
      float radius
    ) {
      float safeRadius = clamp(
        radius,
        0.0,
        min(halfSize.x, halfSize.y)
      );
      vec2 q = abs(point) - halfSize + safeRadius;
      return min(max(q.x, q.y), 0.0)
        + length(max(q, 0.0))
        - safeRadius;
    }

    vec2 roundedBoxNormal(
      vec2 point,
      vec2 halfSize,
      float radius
    ) {
      float safeRadius = clamp(
        radius,
        0.0,
        min(halfSize.x, halfSize.y)
      );
      vec2 pointSign = vec2(
        point.x < 0.0 ? -1.0 : 1.0,
        point.y < 0.0 ? -1.0 : 1.0
      );
      vec2 q = abs(point) - halfSize + safeRadius;
      vec2 cornerVector = max(q, 0.0);

      if (dot(cornerVector, cornerVector) > EPSILON) {
        return safeNormalize(cornerVector) * pointSign;
      }

      if (q.x > q.y) {
        return vec2(pointSign.x, 0.0);
      }

      return vec2(0.0, pointSign.y);
    }

    float gaussian(float distanceSquared, float variance) {
      return exp(-distanceSquared / max(2.0 * variance, EPSILON));
    }

    float schlickFresnel(float cosineTheta, float f0) {
      float grazing = pow(1.0 - saturate(cosineTheta), 5.0);
      return f0 + (1.0 - f0) * grazing;
    }

    vec3 softLight(vec3 base, vec3 blend) {
      vec3 low = 2.0 * base * blend
        + base * base * (1.0 - 2.0 * blend);
      vec3 high = sqrt(max(base, 0.0)) * (2.0 * blend - 1.0)
        + 2.0 * base * (1.0 - blend);
      return mix(low, high, step(vec3(0.5), blend));
    }

    vec3 screenBlend(vec3 base, vec3 blend) {
      return 1.0 - (1.0 - base) * (1.0 - blend);
    }

    vec3 toneMap(vec3 color) {
      color = max(color, 0.0);
      return color / (color + vec3(0.82));
    }

    vec3 toDisplay(vec3 color) {
      // Keep Neutron's approved navy/cobalt/violet identity dominant. Bright
      // Fresnel and caustic values still reach white after tone mapping, while
      // the transmitted scene stays dark enough for security UI contrast.
      color = toneMap(color * 0.18);
      color = pow(color, vec3(1.0 / 2.16));
      return saturate(color);
    }

    vec2 aspectUv(vec2 uv) {
      vec2 centered = uv - 0.5;
      centered.x *= uCssResolution.x / max(uCssResolution.y, 1.0);
      return centered;
    }

    float ribbonField(
      vec2 point,
      float bend,
      float width,
      float phase
    ) {
      float curve = sin(point.x * 2.8 + phase) * bend;
      curve += sin(point.x * 6.1 - phase * 0.63) * bend * 0.18;
      float lineDistance = abs(point.y - curve);
      return 1.0 - smoothstep(width * 0.35, width, lineDistance);
    }

    vec3 neutronBackground(vec2 uv, float time) {
      vec2 point = aspectUv(uv);
      float slowTime = time * 0.045 * uAmbientSpeed;

      // One interpolated value-noise lookup gives the large color fields a
      // natural breakup. The remaining flow is analytic sine motion: unlike
      // multi-octave FBM this stays cheap when background is sampled for RGB
      // dispersion and frost.
      float cloud = valueNoise(
        point * 1.18 + vec2(slowTime * 0.42, -slowTime * 0.31)
      );
      vec2 waveWarp = vec2(
        sin(point.y * 3.1 + slowTime * 1.3),
        cos(point.x * 2.7 - slowTime * 1.1)
      ) * 0.031;
      waveWarp += vec2(
        sin((point.x + point.y) * 5.2 - slowTime) * 0.011,
        cos((point.x - point.y) * 4.6 + slowTime) * 0.009
      );

      vec2 flowed = point + waveWarp + (cloud - 0.5) * 0.026;
      float vertical = saturate(uv.y * 0.84 + 0.08);
      vec3 color = mix(uPalette[0], uPalette[1], vertical * 0.74);

      float cobaltOrb = gaussian(
        dot(flowed - vec2(0.24, -0.14), flowed - vec2(0.24, -0.14)),
        0.115
      );
      float violetOrb = gaussian(
        dot(flowed - vec2(0.62, 0.48), flowed - vec2(0.62, 0.48)),
        0.13
      );
      float cyanOrb = gaussian(
        dot(flowed - vec2(-0.52, -0.38), flowed - vec2(-0.52, -0.38)),
        0.155
      );
      float mintOrb = gaussian(
        dot(flowed - vec2(-0.16, -0.46), flowed - vec2(-0.16, -0.46)),
        0.095
      );

      color += uPalette[2] * cobaltOrb * 1.18;
      color += uPalette[3] * violetOrb * 1.08;
      color += uPalette[4] * cyanOrb * 0.69;
      color += uPalette[5] * mintOrb * 0.44;

      vec2 ribbonPoint = flowed;
      ribbonPoint = mat2(0.91, -0.41, 0.41, 0.91) * ribbonPoint;
      float ribbonA = ribbonField(
        ribbonPoint + vec2(0.02, 0.08),
        0.13,
        0.17,
        slowTime * 2.0
      );
      float ribbonB = ribbonField(
        ribbonPoint * vec2(0.83, 1.0) - vec2(0.16, 0.49),
        0.08,
        0.105,
        1.9 - slowTime
      );

      color += mix(uPalette[5], uPalette[4], 0.42) * ribbonA * 0.28;
      color += mix(uPalette[2], uPalette[3], 0.55) * ribbonB * 0.38;

      // A quiet technical grid gives the lens real spatial information to
      // bend. Derivative-based anti-aliasing keeps it stable when adaptive
      // resolution changes the backing-buffer size.
      vec2 gridCoordinate = uv * uCssResolution / 72.0;
      vec2 gridDistance = abs(
        fract(gridCoordinate - 0.5) - 0.5
      ) / max(fwidth(gridCoordinate), vec2(0.001));
      float gridLine = 1.0 - saturate(
        min(gridDistance.x, gridDistance.y)
      );
      vec3 gridColor = mix(uPalette[4], uPalette[3], uv.x * 0.72);
      color += gridColor * gridLine * 0.024;

      color *= 0.93 + cloud * 0.15;

      float fineGrain = hash21(
        floor(gl_FragCoord.xy * 0.5) + floor(time * 12.0)
      );
      color += (fineGrain - 0.5) * 0.012;

      float vignette = 1.0 - smoothstep(
        0.48,
        1.06,
        length(point * vec2(0.82, 1.05))
      );
      color *= 0.76 + vignette * 0.28;

      return max(color, 0.0);
    }

    struct WindowSample {
      vec3 color;
      float alpha;
      float signedDistance;
      float edgeFactor;
      vec3 normal;
    };

    WindowSample renderWindowMaterial(
      vec2 uv,
      vec2 cssPoint
    ) {
      WindowSample sampleResult;
      vec2 windowCenter = uCssResolution * 0.5;
      vec2 windowHalfSize = max(
        uCssResolution * 0.5 - vec2(1.15),
        vec2(1.0)
      );
      float cornerRadius = clamp(
        uWindowOptics.x,
        0.0,
        min(windowHalfSize.x, windowHalfSize.y)
      );
      vec2 localPoint = cssPoint - windowCenter;
      float signedDistance = signedRoundedBox(
        localPoint,
        windowHalfSize,
        cornerRadius
      );
      float edgeDistance = max(-signedDistance, 0.0);
      float edgeBand = clamp(
        min(uCssResolution.x, uCssResolution.y) * 0.072,
        38.0,
        74.0
      );
      float edgeFactor = 1.0 - smoothstep(
        0.0,
        edgeBand,
        edgeDistance
      );
      vec2 edgeNormal = roundedBoxNormal(
        localPoint,
        windowHalfSize,
        cornerRadius
      );
      vec2 normalizedPoint = localPoint / max(windowHalfSize, vec2(1.0));

      // A shallow full-window meniscus keeps the center stable while the
      // outer 38-74 CSS pixels visibly bend by 14-28 pixels. This is the
      // primary lens; data-liquidglass elements are secondary lenses.
      float radialTerm = dot(normalizedPoint, normalizedPoint);
      float domeDenominator = sqrt(max(0.075, 1.0 - radialTerm * 0.44));
      vec2 domeGradient = normalizedPoint / domeDenominator;
      float ripplePhaseA = normalizedPoint.x * 6.2
        + normalizedPoint.y * 2.7
        + uMotionTime * 0.11;
      float ripplePhaseB = normalizedPoint.y * 7.1
        - normalizedPoint.x * 1.9
        - uMotionTime * 0.085;
      float movingRipple = sin(ripplePhaseA)
        * cos(ripplePhaseB)
        * 0.5;
      vec2 rippleGradient = vec2(
        cos(ripplePhaseA) * cos(ripplePhaseB),
        -sin(ripplePhaseA) * sin(ripplePhaseB)
      ) * 0.5;
      vec2 opticalGradient = mix(
        domeGradient * 0.20,
        edgeNormal,
        edgeFactor * 0.94
      );
      opticalGradient += rippleGradient * (0.025 + edgeFactor * 0.07);

      float windowDepth = max(uWindowOptics.y, 0.05);
      vec3 surfaceNormal = safeNormalize(vec3(
        -opticalGradient.x * windowDepth * 0.84,
        -opticalGradient.y * windowDepth * 0.84,
        1.0
      ));
      vec3 incident = vec3(0.0, 0.0, -1.0);
      float eta = 1.0 / mix(
        1.22,
        1.52,
        saturate(windowDepth * 0.58)
      );
      vec3 transmitted = refract(incident, surfaceNormal, eta);
      vec2 snellDirection = transmitted.xy
        / max(abs(transmitted.z), 0.14);

      float refractionAmount = uWindowOptics.z * uRefractionScale;
      float bendPixels = mix(
        14.0,
        28.0,
        saturate(windowDepth * 0.67)
      );
      bendPixels *= mix(0.075, 1.0, edgeFactor);
      vec2 displacement = (
        snellDirection + opticalGradient * 0.31
      ) * bendPixels * refractionAmount
        / max(uCssResolution, vec2(1.0));
      vec2 refractedUv = saturate(uv + displacement);

      float dispersion = uWindowOptics.w * uDispersionScale;
      vec2 spectralDirection = safeNormalize(
        edgeNormal * 0.74 + opticalGradient + vec2(0.0001)
      );
      float spectralPixels = mix(0.45, 3.25, edgeFactor)
        * dispersion;
      vec2 spectralOffset = spectralDirection * spectralPixels
        / max(uCssResolution, vec2(1.0));

      vec3 centerSample = neutronBackground(refractedUv, uMotionTime);
      vec3 color = centerSample;

      // The outer RGB split only exists in the curved meniscus. Avoid two
      // complete procedural samples for the flat majority of the window.
      if (edgeFactor > 0.012 && dispersion > 0.002) {
        vec3 redSample = neutronBackground(
          saturate(refractedUv + spectralOffset * 1.12),
          uMotionTime
        );
        vec3 blueSample = neutronBackground(
          saturate(refractedUv - spectralOffset * 1.31),
          uMotionTime
        );
        color = vec3(
          redSample.r,
          centerSample.g,
          blueSample.b
        );
      }

      vec3 viewDirection = vec3(0.0, 0.0, 1.0);
      float cosineTheta = saturate(dot(viewDirection, surfaceNormal));
      float fresnel = schlickFresnel(cosineTheta, 0.042);
      float windowSpecular = uWindowMaterial.x * uSpecularScale;
      float windowCaustics = uWindowMaterial.y * uCausticsScale;

      vec3 topLight = safeNormalize(vec3(-0.48, 0.82, 0.86));
      vec3 sideLight = safeNormalize(vec3(0.88, -0.18, 0.62));
      vec3 topHalf = safeNormalize(topLight + viewDirection);
      vec3 sideHalf = safeNormalize(sideLight + viewDirection);
      float topSpecular = pow(
        saturate(dot(surfaceNormal, topHalf)),
        74.0
      );
      float sideSpecular = pow(
        saturate(dot(surfaceNormal, sideHalf)),
        42.0
      );

      vec3 reflectedTone = mix(
        vec3(0.39, 0.73, 1.0),
        vec3(0.78, 0.58, 1.0),
        saturate(uv.x * 0.7 + uv.y * 0.3)
      );
      color = mix(
        color,
        screenBlend(color, reflectedTone),
        fresnel * (0.34 + edgeFactor * 0.38)
      );
      color += vec3(0.91, 0.98, 1.0)
        * topSpecular
        * windowSpecular
        * (0.18 + edgeFactor * 0.34);
      color += vec3(0.58, 0.82, 1.0)
        * sideSpecular
        * windowSpecular
        * 0.19;

      float causticPhase = dot(
        cssPoint,
        safeNormalize(vec2(0.92, 0.39))
      ) * 0.043;
      causticPhase += movingRipple * 5.7 - uMotionTime * 0.15;
      float causticBand = pow(
        0.5 + 0.5 * sin(causticPhase),
        9.0
      );
      vec3 causticColor = mix(
        vec3(0.22, 0.91, 1.0),
        vec3(0.78, 0.48, 1.0),
        0.5 + 0.5 * sin(causticPhase * 0.23)
      );
      color += causticColor
        * causticBand
        * edgeFactor
        * dispersion
        * windowCaustics
        * 0.22;

      float antialiasWidth = max(fwidth(signedDistance), 0.72);
      float coverage = 1.0 - smoothstep(
        -antialiasWidth,
        antialiasWidth,
        signedDistance
      );
      float rim = 1.0 - smoothstep(
        0.0,
        max(2.8, antialiasWidth * 3.2),
        edgeDistance
      );
      float secondaryRim = 1.0 - smoothstep(1.4, 8.5, edgeDistance);
      float topBias = saturate(0.5 + edgeNormal.y * 0.5);
      float leftBias = saturate(0.5 - edgeNormal.x * 0.5);
      vec3 rimColor = mix(
        vec3(0.45, 0.78, 1.0),
        vec3(0.96, 1.0, 1.0),
        topBias
      );
      rimColor = mix(
        rimColor,
        vec3(0.74, 0.57, 1.0),
        (1.0 - leftBias) * 0.48
      );
      color += rimColor * rim * (0.34 + fresnel * 0.66);
      color += vec3(0.88, 0.96, 1.0)
        * secondaryRim
        * topBias
        * 0.12;

      // A broad highlight across the draggable title region makes it clear
      // that the titlebar and dashboard are one continuous piece of glass.
      float titlebarHighlight = smoothstep(0.86, 1.0, uv.y)
        * smoothstep(0.0, 0.42, uv.x)
        * (1.0 - smoothstep(0.58, 1.0, uv.x));
      color += vec3(0.72, 0.84, 1.0)
        * titlebarHighlight
        * (0.035 + fresnel * 0.07);

      sampleResult.color = max(color, 0.0);
      sampleResult.alpha = coverage;
      sampleResult.signedDistance = signedDistance;
      sampleResult.edgeFactor = edgeFactor;
      sampleResult.normal = surfaceNormal;
      return sampleResult;
    }

    vec3 sampleFrostedBackground(
      vec2 uv,
      float time,
      float frost,
      vec2 tangent
    ) {
      float radius = frost * uFrostScale;
      vec2 pixel = 1.0 / max(uResolution, vec2(1.0));
      vec2 axisA = safeNormalize(tangent + vec2(0.0001, 0.0));
      vec2 axisB = vec2(-axisA.y, axisA.x);
      vec2 tapA = axisA * pixel * (3.0 + radius * 12.0);
      vec2 tapB = axisB * pixel * (3.0 + radius * 12.0);

      vec3 center = neutronBackground(uv, time);

      if (uQuality <= 0 || radius < 0.025) {
        return center;
      }

      vec3 color = center * 0.56;
      color += neutronBackground(uv + tapA, time) * 0.11;
      color += neutronBackground(uv - tapA, time) * 0.11;
      color += neutronBackground(uv + tapB, time) * 0.11;
      color += neutronBackground(uv - tapB, time) * 0.11;
      return color;
    }

    struct SurfaceHit {
      int index;
      float signedDistance;
      float edgeDistance;
      vec2 localPoint;
      vec2 halfSize;
      float radius;
    };

    SurfaceHit findSurface(vec2 cssPoint) {
      SurfaceHit hit;
      hit.index = -1;
      hit.signedDistance = 1000000.0;
      hit.edgeDistance = 1000000.0;
      hit.localPoint = vec2(0.0);
      hit.halfSize = vec2(1.0);
      hit.radius = 0.0;

      for (int index = 0; index < MAX_SURFACES; index += 1) {
        if (index >= uSurfaceCount) {
          break;
        }

        vec4 rect = uSurfaceRects[index];
        vec4 optics = uSurfaceOptics[index];
        vec2 localPoint = cssPoint - rect.xy;

        // Most pixels are not inside most DOM surfaces. Reject them with two
        // comparisons before evaluating the rounded-corner square root.
        vec2 absolutePoint = abs(localPoint);
        if (
          absolutePoint.x > rect.z
          || absolutePoint.y > rect.w
        ) {
          continue;
        }

        float distanceToSurface = signedRoundedBox(
          localPoint,
          rect.zw,
          optics.x
        );

        // Later DOM elements win in overlaps, matching ordinary paint order.
        if (distanceToSurface <= 0.0) {
          hit.index = index;
          hit.signedDistance = distanceToSurface;
          hit.edgeDistance = -distanceToSurface;
          hit.localPoint = localPoint;
          hit.halfSize = rect.zw;
          hit.radius = optics.x;
        }
      }

      return hit;
    }

    float surfaceHeight(
      float edgeDistance,
      vec2 localPoint,
      vec2 halfSize,
      float depth
    ) {
      float shortAxis = max(min(halfSize.x, halfSize.y), 1.0);
      float edgeBand = clamp(shortAxis * 0.23, 15.0, 78.0);
      float edgeRise = smoothstep(0.0, edgeBand, edgeDistance);
      float innerPlateau = smoothstep(
        edgeBand,
        edgeBand * 2.5,
        edgeDistance
      );
      vec2 normalizedPoint = localPoint / max(halfSize, vec2(1.0));
      float dome = sqrt(
        max(0.0, 1.0 - dot(normalizedPoint, normalizedPoint) * 0.32)
      );
      float profile = mix(edgeRise, dome, innerPlateau * 0.42);
      return profile * max(depth, 0.0);
    }

    vec2 interactiveNormal(
      vec2 cssPoint,
      vec2 baseNormal,
      float interactive,
      float depth
    ) {
      if (interactive < 0.5 || uPointer.z < 0.001) {
        return baseNormal;
      }

      vec2 pointerDelta = cssPoint - uPointer.xy;
      float pointerDistance = length(pointerDelta);
      float radius = mix(115.0, 165.0, saturate(depth * 0.5));
      float influence = exp(
        -(pointerDistance * pointerDistance)
        / max(radius * radius, 1.0)
      );
      float pressure = mix(0.46, 1.0, uPointer.w);
      vec2 pointerNormal = safeNormalize(pointerDelta + vec2(0.001));
      vec2 velocityShear = uPointerMotion.xy * 0.0018;

      return safeNormalize(
        baseNormal
        + pointerNormal * influence * pressure * 0.72
        - velocityShear * influence * 0.35
      );
    }

    vec3 renderGlassSurface(
      vec2 uv,
      vec2 cssPoint,
      SurfaceHit hit,
      vec3 untouchedBackground
    ) {
      int index = hit.index;
      vec4 optics = uSurfaceOptics[index];
      vec4 material = uSurfaceMaterial[index];
      vec4 tint = uSurfaceTint[index];

      float depth = max(optics.y, 0.01);
      float refractionStrength = optics.z * uRefractionScale;
      float dispersion = optics.w * uDispersionScale;
      float frost = saturate(material.x) * uFrostScale;
      float specularStrength = material.y * uSpecularScale;
      float interactive = material.z;
      float opacity = saturate(material.w);

      vec2 geometricNormal = roundedBoxNormal(
        hit.localPoint,
        hit.halfSize,
        hit.radius
      );
      geometricNormal = interactiveNormal(
        cssPoint,
        geometricNormal,
        interactive,
        depth
      );

      float shortAxis = max(min(hit.halfSize.x, hit.halfSize.y), 1.0);
      float edgeBand = clamp(shortAxis * 0.24, 18.0, 88.0);
      float edgeProximity = 1.0 - smoothstep(
        0.0,
        edgeBand,
        hit.edgeDistance
      );
      float lensHeight = surfaceHeight(
        hit.edgeDistance,
        hit.localPoint,
        hit.halfSize,
        depth
      );

      vec2 normalizedLocal = hit.localPoint / max(hit.halfSize, vec2(1.0));
      vec2 domeGradient = normalizedLocal
        / max(sqrt(max(0.08, 1.0 - dot(normalizedLocal, normalizedLocal) * 0.34)), 0.2);
      vec2 opticalGradient = mix(
        domeGradient * 0.34,
        geometricNormal,
        edgeProximity
      );

      float surfacePhaseA = normalizedLocal.x * 7.4
        + normalizedLocal.y * 2.1
        + uMotionTime * 0.13
        + float(index) * 1.731;
      float surfacePhaseB = normalizedLocal.y * 6.7
        - normalizedLocal.x * 2.8
        - uMotionTime * 0.09
        + float(index) * 0.917;
      float liquidNoise = sin(surfacePhaseA)
        * cos(surfacePhaseB)
        * 0.5;
      vec2 noiseNormal = vec2(
        cos(surfacePhaseA) * cos(surfacePhaseB),
        -sin(surfacePhaseA) * sin(surfacePhaseB)
      ) * 0.5;
      opticalGradient += noiseNormal * (0.08 + edgeProximity * 0.12);

      vec3 surfaceNormal = safeNormalize(vec3(
        -opticalGradient.x * depth * 0.62,
        -opticalGradient.y * depth * 0.62,
        1.0
      ));
      vec3 viewDirection = vec3(0.0, 0.0, 1.0);

      // Snell-inspired offset. The incident direction is almost normal to a
      // UI pane; the curved height field provides the visible lateral bend.
      float eta = 1.0 / mix(1.18, 1.52, saturate(depth * 0.5));
      vec3 incident = vec3(0.0, 0.0, -1.0);
      vec3 transmitted = refract(incident, surfaceNormal, eta);
      vec2 physicalBend = transmitted.xy
        / max(abs(transmitted.z), 0.16);

      float displacementPixels = refractionStrength
        * mix(4.0, 34.0, saturate(depth * 0.62))
        * (0.32 + edgeProximity * 0.96);
      vec2 displacement = (
        physicalBend
        + opticalGradient * 0.34
      ) * displacementPixels / max(uCssResolution, vec2(1.0));

      vec2 refractedUv = saturate(uv + displacement);
      vec2 tangent = vec2(-geometricNormal.y, geometricNormal.x);
      vec2 spectralAxis = safeNormalize(
        opticalGradient + geometricNormal * 0.25 + vec2(0.0001)
      );
      vec2 spectralOffset = spectralAxis
        * dispersion
        * mix(0.65, 3.7, edgeProximity)
        / max(uCssResolution, vec2(1.0));

      vec3 baseSample = sampleFrostedBackground(
        refractedUv,
        uMotionTime,
        frost,
        tangent
      );

      vec3 refractedColor = baseSample;
      if (dispersion > 0.002) {
        // Frost is evaluated only once. Chromatic fringe channels are narrow
        // single samples; repeating the blur kernel for red and blue would
        // triple the most expensive part of a glass fragment.
        vec3 redSample = neutronBackground(
          saturate(refractedUv + spectralOffset * 1.16),
          uMotionTime
        );
        vec3 greenSample = baseSample;
        vec3 blueSample = neutronBackground(
          saturate(refractedUv - spectralOffset * 1.32),
          uMotionTime
        );
        refractedColor = vec3(
          redSample.r,
          greenSample.g,
          blueSample.b
        );
      }

      float cosTheta = saturate(dot(viewDirection, surfaceNormal));
      float fresnel = schlickFresnel(cosTheta, 0.035);

      vec3 keyDirection = safeNormalize(vec3(-0.62, 0.73, 0.92));
      vec3 fillDirection = safeNormalize(vec3(0.76, -0.42, 0.74));
      vec3 halfKey = safeNormalize(keyDirection + viewDirection);
      vec3 halfFill = safeNormalize(fillDirection + viewDirection);
      float keySpecular = pow(
        saturate(dot(surfaceNormal, halfKey)),
        mix(28.0, 92.0, saturate(1.0 - frost))
      );
      float fillSpecular = pow(
        saturate(dot(surfaceNormal, halfFill)),
        mix(18.0, 58.0, saturate(1.0 - frost))
      );

      vec2 pointerVector = uPointer.xy - cssPoint;
      float pointerDistance = length(pointerVector);
      float pointerGlow = exp(
        -(pointerDistance * pointerDistance)
        / (190.0 * 190.0)
      ) * interactive * uPointer.z;
      vec3 pointerDirection = safeNormalize(vec3(
        pointerVector / max(uCssResolution, vec2(1.0)),
        0.24
      ));
      vec3 pointerHalf = safeNormalize(pointerDirection + viewDirection);
      float pointerSpecular = pow(
        saturate(dot(surfaceNormal, pointerHalf)),
        48.0
      ) * pointerGlow;

      float curvature = edgeProximity * (0.45 + depth * 0.32);
      float causticPhase = dot(
        cssPoint,
        safeNormalize(vec2(0.83, 0.56))
      ) * 0.048;
      causticPhase += liquidNoise * 4.2;
      causticPhase -= uMotionTime * 0.18;
      float causticBands = pow(
        0.5 + 0.5 * sin(causticPhase),
        7.0
      );
      float caustics = causticBands
        * curvature
        * dispersion
        * uCausticsScale;

      float rimWidth = max(fwidth(hit.signedDistance) * 1.35, 0.7);
      float outerRim = 1.0 - smoothstep(
        0.0,
        rimWidth * 2.2,
        hit.edgeDistance
      );
      float innerRim = 1.0 - smoothstep(
        1.2,
        5.4,
        hit.edgeDistance
      );
      float topBias = saturate(0.52 + geometricNormal.y * 0.48);
      float leftBias = saturate(0.52 - geometricNormal.x * 0.48);
      // Every marked pane participates in the same moving optical field.
      // The previous specular-only gate made the broad background ribbon
      // visible on just a few showcase cards. Weighting the material inputs
      // lets smaller sidebar, status and result panes bend that same field at
      // a softer amplitude, without introducing a separate painted gradient.
      float showcaseSurface = smoothstep(
        0.60,
        1.34,
        refractionStrength * 0.62
          + depth * 0.28
          + specularStrength * 0.22
          + dispersion * 0.15
      );

      vec3 glassColor = refractedColor;

      // Large showcase panes use high specular values. Strengthen the actual
      // refracted-background delta on those panes so a smooth wallpaper still
      // reveals where the lens bends it. This is not a painted tint: when the
      // sampled background does not move, the delta remains zero.
      glassColor += (
        refractedColor - untouchedBackground
      ) * showcaseSurface * 1.08;

      glassColor = mix(
        glassColor,
        glassColor * (0.82 + tint.rgb * 0.38),
        saturate(tint.a)
      );

      float density = saturate(0.055 + frost * 0.18 + depth * 0.025);
      vec3 densityTint = mix(
        vec3(0.78, 0.88, 1.0),
        tint.rgb,
        saturate(tint.a + 0.16)
      );
      glassColor = mix(glassColor, densityTint, density);

      vec3 reflection = mix(
        vec3(0.52, 0.76, 1.0),
        vec3(0.82, 0.64, 1.0),
        saturate(uv.x * 0.75 + uv.y * 0.25)
      );
      glassColor = mix(
        glassColor,
        screenBlend(glassColor, reflection),
        fresnel * (0.26 + edgeProximity * 0.42)
      );

      if (showcaseSurface > 0.001) {
        // A coherent moving reflection makes the curvature readable at a
        // glance. A narrow white core sits inside a wider tinted halo, while
        // the top-meniscus term catches the pane's upper shoulder. The band
        // follows the same normalized lens coordinates as refraction.
        vec2 showcaseAxis = safeNormalize(vec2(0.78, 0.62));
        float showcaseTravel = sin(
          uMotionTime * 0.24 + float(index) * 0.91
        ) * 0.42;
        float showcaseDistance = abs(
          dot(normalizedLocal, showcaseAxis) - showcaseTravel
        );
        float showcaseCore = exp(
          -showcaseDistance * showcaseDistance * 210.0
        );
        float showcaseHalo = exp(
          -showcaseDistance * showcaseDistance * 31.0
        );
        float topMeniscus = exp(
          -pow((normalizedLocal.y - 0.76) * 5.2, 2.0)
        ) * smoothstep(-1.0, 0.72, normalizedLocal.x);
        float interiorMask = 1.0 - edgeProximity * 0.48;
        vec3 showcaseColor = mix(
          vec3(0.66, 0.88, 1.0),
          vec3(0.93, 1.0, 0.98),
          showcaseCore
        );
        showcaseColor = mix(
          showcaseColor,
          tint.rgb * 0.58 + vec3(0.48),
          0.28
        );
        glassColor += showcaseColor
          * interiorMask
          * showcaseSurface
          * (
            showcaseCore * 0.19
            + showcaseHalo * 0.085
            + topMeniscus * 0.11
          );
      }

      vec3 specularColor = vec3(0.87, 0.97, 1.0) * keySpecular;
      specularColor += vec3(0.62, 0.84, 1.0) * fillSpecular * 0.46;
      specularColor += vec3(0.72, 1.0, 0.93) * pointerSpecular * 0.76;
      specularColor *= specularStrength;
      glassColor += specularColor;

      vec3 causticColor = mix(
        vec3(0.31, 0.92, 1.0),
        vec3(0.78, 0.57, 1.0),
        sin(causticPhase * 0.31) * 0.5 + 0.5
      );
      glassColor += causticColor * caustics * 0.22;

      // A broad pane still needs readable optical movement away from its
      // bevel. Two coherent waves form a restrained interior caustic instead
      // of placing decorative gradients over the DOM surface. Its strength
      // follows the material depth and refraction values, so larger security
      // cards can look like shaped glass without making tiny controls noisy.
      float interiorWave = 0.5 + 0.5 * sin(
        surfacePhaseA * 0.58
        + sin(surfacePhaseB * 0.74) * 1.65
        + normalizedLocal.y * 3.1
      );
      float interiorCaustic = pow(interiorWave, 9.0)
        * (1.0 - edgeProximity * 0.72)
        * saturate(depth * 0.72)
        * saturate(refractionStrength * 0.82)
        * uCausticsScale;
      glassColor += causticColor
        * interiorCaustic
        * (0.026 + dispersion * 0.034);

      vec3 rimColor = mix(
        vec3(0.48, 0.86, 1.0),
        vec3(0.95, 1.0, 1.0),
        topBias
      );
      rimColor = mix(rimColor, vec3(0.73, 0.62, 1.0), 1.0 - leftBias);
      glassColor += rimColor
        * outerRim
        * (0.28 + specularStrength * 0.18);
      glassColor += vec3(0.92, 0.98, 1.0)
        * innerRim
        * topBias
        * 0.16;

      float interiorShadow = edgeProximity
        * (1.0 - topBias)
        * (0.06 + depth * 0.035);
      glassColor *= 1.0 - interiorShadow;

      // Opacity controls optical material strength, never canvas alpha. That
      // keeps the shared background continuous beneath DOM text and icons.
      glassColor = mix(untouchedBackground, glassColor, opacity);

      if (uDebug == 1) {
        vec3 debugTint = vec3(
          hash11(float(index) * 3.1 + 1.0),
          hash11(float(index) * 4.7 + 2.0),
          hash11(float(index) * 6.3 + 3.0)
        );
        glassColor = mix(glassColor, debugTint, 0.12);
        glassColor += debugTint * outerRim * 0.62;
      }

      if (uDebug == 2) {
        glassColor = vec3(
          edgeProximity,
          fresnel,
          saturate(length(displacement) * 24.0)
        );
      }

      if (uDebug == 3) {
        glassColor = surfaceNormal * 0.5 + 0.5;
      }

      return max(glassColor, 0.0);
    }

    void main() {
      vec2 uv = gl_FragCoord.xy / max(uResolution, vec2(1.0));
      vec2 cssPoint = vec2(
        uv.x * uCssResolution.x,
        uv.y * uCssResolution.y
      );

      WindowSample windowSample = renderWindowMaterial(uv, cssPoint);

      if (windowSample.alpha <= 0.001) {
        discard;
      }

      vec3 background = windowSample.color;
      SurfaceHit hit = findSurface(cssPoint);
      vec3 color = background;

      if (hit.index >= 0) {
        color = renderGlassSurface(
          uv,
          cssPoint,
          hit,
          background
        );
      }

      color = toDisplay(color);
      if (uDebug == 4) {
        color = windowSample.normal * 0.5 + 0.5;
      }

      outColor = vec4(
        color,
        windowSample.alpha * uRootBackgroundAlpha
      );
    }
  `;

  function clamp(value, minimum, maximum) {
    return Math.min(maximum, Math.max(minimum, value));
  }

  function lerp(start, end, amount) {
    return start + (end - start) * amount;
  }

  function damp(current, target, smoothing, deltaSeconds) {
    const frameAdjusted = 1 - Math.pow(1 - smoothing, deltaSeconds * 60);
    return lerp(current, target, frameAdjusted);
  }

  function finiteOr(value, fallback) {
    if (
      value == null
      || (typeof value === 'string' && value.trim() === '')
    ) {
      return fallback;
    }

    const numeric = Number(value);
    return Number.isFinite(numeric) ? numeric : fallback;
  }

  function parseBoundedNumber(value, fallback, minimum, maximum) {
    return clamp(finiteOr(value, fallback), minimum, maximum);
  }

  function parseBoolean(value, fallback = false) {
    if (value == null || value === '') {
      return fallback;
    }

    const normalized = String(value).trim().toLowerCase();

    if (
      normalized === 'true'
      || normalized === '1'
      || normalized === 'yes'
      || normalized === 'on'
      || normalized === 'interactive'
    ) {
      return true;
    }

    if (
      normalized === 'false'
      || normalized === '0'
      || normalized === 'no'
      || normalized === 'off'
      || normalized === 'none'
    ) {
      return false;
    }

    return fallback;
  }

  function parseCssRadius(style, elementRect, fallback) {
    const raw = style.borderTopLeftRadius || '';
    const firstComponent = raw.split(/[ /]/)[0];
    const numeric = Number.parseFloat(firstComponent);

    if (!Number.isFinite(numeric)) {
      return fallback;
    }

    if (firstComponent.endsWith('%')) {
      return clamp(
        numeric * 0.01 * Math.min(elementRect.width, elementRect.height),
        0,
        Math.min(elementRect.width, elementRect.height) * 0.5
      );
    }

    return clamp(
      numeric,
      0,
      Math.min(elementRect.width, elementRect.height) * 0.5
    );
  }

  function parseHexColor(value) {
    if (typeof value !== 'string') {
      return null;
    }

    const normalized = value.trim().replace(/^#/, '');

    if (!/^[0-9a-f]{3,8}$/i.test(normalized)) {
      return null;
    }

    let red;
    let green;
    let blue;
    let alpha = 255;

    if (normalized.length === 3 || normalized.length === 4) {
      red = Number.parseInt(normalized[0] + normalized[0], 16);
      green = Number.parseInt(normalized[1] + normalized[1], 16);
      blue = Number.parseInt(normalized[2] + normalized[2], 16);

      if (normalized.length === 4) {
        alpha = Number.parseInt(normalized[3] + normalized[3], 16);
      }
    } else if (normalized.length === 6 || normalized.length === 8) {
      red = Number.parseInt(normalized.slice(0, 2), 16);
      green = Number.parseInt(normalized.slice(2, 4), 16);
      blue = Number.parseInt(normalized.slice(4, 6), 16);

      if (normalized.length === 8) {
        alpha = Number.parseInt(normalized.slice(6, 8), 16);
      }
    } else {
      return null;
    }

    return [
      red / 255,
      green / 255,
      blue / 255,
      alpha / 255,
    ];
  }

  function parseRgbColor(value) {
    if (typeof value !== 'string') {
      return null;
    }

    const match = value.trim().match(
      /^rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:\s*[,/]\s*([\d.]+)%?)?\s*\)$/i
    );

    if (!match) {
      return null;
    }

    const alpha = match[4] == null
      ? 1
      : clamp(Number(match[4]), 0, 1);

    return [
      clamp(Number(match[1]) / 255, 0, 1),
      clamp(Number(match[2]) / 255, 0, 1),
      clamp(Number(match[3]) / 255, 0, 1),
      alpha,
    ];
  }

  function parseColor(value, fallback) {
    return parseHexColor(value)
      || parseRgbColor(value)
      || fallback.slice();
  }

  function nowSeconds() {
    return global.performance.now() * 0.001;
  }

  function isElementVisible(element, rect, style) {
    if (!element.isConnected) {
      return false;
    }

    if (element.hidden || element.hasAttribute('data-glass-disabled')) {
      return false;
    }

    if (
      style.display === 'none'
      || style.visibility === 'hidden'
      || Number(style.opacity) <= 0.001
    ) {
      return false;
    }

    if (rect.width < 1 || rect.height < 1) {
      return false;
    }

    if (
      rect.right < 0
      || rect.bottom < 0
      || rect.left > global.innerWidth
      || rect.top > global.innerHeight
    ) {
      return false;
    }

    return true;
  }

  function mergeOptions(base, override) {
    const options = Object.assign({}, base, override || {});
    options.palette = Object.assign(
      {},
      base.palette,
      override && override.palette ? override.palette : {}
    );
    return options;
  }

  function dispatchEngineEvent(name, detail) {
    global.dispatchEvent(new CustomEvent(`liquidglass:${name}`, { detail }));
  }

  class SignalHub {
    constructor() {
      this.listeners = new Map();
    }

    on(name, listener) {
      if (typeof listener !== 'function') {
        return () => {};
      }

      if (!this.listeners.has(name)) {
        this.listeners.set(name, new Set());
      }

      const listeners = this.listeners.get(name);
      listeners.add(listener);

      return () => {
        listeners.delete(listener);
      };
    }

    emit(name, payload) {
      const listeners = this.listeners.get(name);

      if (!listeners) {
        return;
      }

      for (const listener of listeners) {
        try {
          listener(payload);
        } catch (error) {
          console.error(`[${ENGINE_NAME}] signal listener failed`, error);
        }
      }
    }

    clear() {
      this.listeners.clear();
    }
  }

  class PointerState {
    constructor(options) {
      this.options = options;
      this.position = { x: 0, y: 0 };
      this.target = { x: 0, y: 0 };
      this.previousTarget = { x: 0, y: 0 };
      this.velocity = { x: 0, y: 0 };
      this.targetVelocity = { x: 0, y: 0 };
      this.inside = false;
      this.down = false;
      this.pressure = 0;
      this.pointerType = 'mouse';
      this.lastEventTime = 0;
      this.abortController = null;
    }

    attach(target) {
      this.detach();
      this.abortController = new AbortController();
      const signal = this.abortController.signal;

      target.addEventListener(
        'pointermove',
        (event) => this.handleMove(event),
        { passive: true, signal }
      );
      target.addEventListener(
        'pointerenter',
        (event) => this.handleEnter(event),
        { passive: true, signal }
      );
      target.addEventListener(
        'pointerleave',
        () => this.handleLeave(),
        { passive: true, signal }
      );
      target.addEventListener(
        'pointerdown',
        (event) => this.handleDown(event),
        { passive: true, signal }
      );
      target.addEventListener(
        'pointerup',
        (event) => this.handleUp(event),
        { passive: true, signal }
      );
      target.addEventListener(
        'pointercancel',
        () => this.handleLeave(),
        { passive: true, signal }
      );
    }

    detach() {
      if (this.abortController) {
        this.abortController.abort();
        this.abortController = null;
      }
    }

    updateTarget(event) {
      this.previousTarget.x = this.target.x;
      this.previousTarget.y = this.target.y;
      this.target.x = event.clientX;
      this.target.y = global.innerHeight - event.clientY;

      const timestamp = event.timeStamp * 0.001;
      const elapsed = clamp(timestamp - this.lastEventTime, 1 / 240, 0.1);
      this.targetVelocity.x = (
        this.target.x - this.previousTarget.x
      ) / elapsed;
      this.targetVelocity.y = (
        this.target.y - this.previousTarget.y
      ) / elapsed;
      this.lastEventTime = timestamp;
      this.pointerType = event.pointerType || 'mouse';
    }

    handleMove(event) {
      this.inside = true;
      this.updateTarget(event);

      if (event.pressure > 0) {
        this.pressure = event.pressure;
      }
    }

    handleEnter(event) {
      this.inside = true;
      this.updateTarget(event);
      this.position.x = this.target.x;
      this.position.y = this.target.y;
    }

    handleLeave() {
      this.inside = false;
      this.down = false;
      this.pressure = 0;
    }

    handleDown(event) {
      this.inside = true;
      this.down = true;
      this.pressure = event.pressure || 0.7;
      this.updateTarget(event);
    }

    handleUp(event) {
      this.down = false;
      this.pressure = 0;
      this.updateTarget(event);
    }

    tick(deltaSeconds) {
      const smoothing = this.options.pointerSmoothing;
      this.position.x = damp(
        this.position.x,
        this.target.x,
        smoothing,
        deltaSeconds
      );
      this.position.y = damp(
        this.position.y,
        this.target.y,
        smoothing,
        deltaSeconds
      );

      this.velocity.x = damp(
        this.velocity.x,
        this.targetVelocity.x,
        0.18,
        deltaSeconds
      );
      this.velocity.y = damp(
        this.velocity.y,
        this.targetVelocity.y,
        0.18,
        deltaSeconds
      );

      const decay = Math.pow(
        this.options.pointerVelocityDecay,
        deltaSeconds * 60
      );
      this.targetVelocity.x *= decay;
      this.targetVelocity.y *= decay;

      if (!this.inside) {
        this.pressure = damp(this.pressure, 0, 0.18, deltaSeconds);
      }
    }

    toUniform() {
      return [
        this.position.x,
        this.position.y,
        this.inside ? this.options.pointerInfluence : 0,
        this.down ? Math.max(this.pressure, 0.55) : this.pressure,
      ];
    }

    motionUniform() {
      return [
        this.velocity.x,
        this.velocity.y,
        this.pointerType === 'touch' ? 1 : 0,
        0,
      ];
    }
  }

  class SurfaceRecord {
    constructor(element, ordinal) {
      this.element = element;
      this.ordinal = ordinal;
      this.visible = false;
      this.rect = new Float32Array(4);
      this.optics = new Float32Array(4);
      this.material = new Float32Array(4);
      this.tint = new Float32Array(4);
      this.sourceRect = null;
      this.revision = 0;
      this.lastMeasuredAt = 0;
    }

    measure(viewportHeight) {
      const element = this.element;
      const domRect = element.getBoundingClientRect();
      const style = global.getComputedStyle(element);

      this.visible = isElementVisible(element, domRect, style);

      if (!this.visible) {
        return false;
      }

      const defaultRadius = parseCssRadius(style, domRect, 24);
      const radius = parseBoundedNumber(
        element.dataset.glassRadius,
        defaultRadius,
        0,
        Math.min(domRect.width, domRect.height) * 0.5
      );
      const depth = parseBoundedNumber(
        element.dataset.glassDepth,
        0.9,
        0.05,
        2.5
      );
      const refraction = parseBoundedNumber(
        element.dataset.glassRefraction,
        1,
        0,
        2.5
      );
      const dispersion = parseBoundedNumber(
        element.dataset.glassDispersion,
        0.42,
        0,
        2.5
      );
      const frost = parseBoundedNumber(
        element.dataset.glassFrost,
        0.16,
        0,
        1
      );
      const specular = parseBoundedNumber(
        element.dataset.glassSpecular,
        1,
        0,
        2.5
      );
      const interactive = parseBoolean(
        element.dataset.glassInteractive,
        element.matches('button, a, input, select, [role="button"]')
      );
      const opacity = parseBoundedNumber(
        element.dataset.glassOpacity,
        1,
        0,
        1
      );

      const cssTint = style.getPropertyValue('--liquidglass-tint').trim();
      const tint = parseColor(
        element.dataset.glassTint || cssTint,
        [0.42, 0.68, 1, 0.14]
      );
      const explicitTintAmount = style
        .getPropertyValue('--liquidglass-tint-amount')
        .trim();
      const tintAmount = parseBoundedNumber(
        explicitTintAmount,
        tint[3],
        0,
        1
      );

      const centerX = domRect.left + domRect.width * 0.5;
      const centerY = viewportHeight - (
        domRect.top + domRect.height * 0.5
      );

      this.rect[0] = centerX;
      this.rect[1] = centerY;
      this.rect[2] = domRect.width * 0.5;
      this.rect[3] = domRect.height * 0.5;

      this.optics[0] = radius;
      this.optics[1] = depth;
      this.optics[2] = refraction;
      this.optics[3] = dispersion;

      this.material[0] = frost;
      this.material[1] = specular;
      this.material[2] = interactive ? 1 : 0;
      this.material[3] = opacity;

      this.tint[0] = tint[0];
      this.tint[1] = tint[1];
      this.tint[2] = tint[2];
      this.tint[3] = tintAmount;

      this.sourceRect = {
        left: domRect.left,
        top: domRect.top,
        width: domRect.width,
        height: domRect.height,
      };
      this.revision += 1;
      this.lastMeasuredAt = global.performance.now();
      return true;
    }

    snapshot() {
      return {
        ordinal: this.ordinal,
        tagName: this.element.tagName.toLowerCase(),
        id: this.element.id || null,
        classes: Array.from(this.element.classList),
        glassId: this.element.dataset.glassId || null,
        visible: this.visible,
        rect: Array.from(this.rect),
        optics: {
          radius: this.optics[0],
          depth: this.optics[1],
          refraction: this.optics[2],
          dispersion: this.optics[3],
        },
        material: {
          frost: this.material[0],
          specular: this.material[1],
          interactive: this.material[2] > 0.5,
          opacity: this.material[3],
        },
        tint: Array.from(this.tint),
        revision: this.revision,
      };
    }
  }

  class SurfaceRegistry {
    constructor(root, options, signalHub) {
      this.root = root;
      this.options = options;
      this.signalHub = signalHub;
      this.records = [];
      this.recordMap = new WeakMap();
      this.visibleRecords = [];
      this.revision = 0;
      this.lastMeasureTime = -Infinity;
      this.measureQueued = true;
      this.resizeObserver = null;
      this.mutationObserver = null;
      this.abortController = null;
    }

    attach() {
      this.detach();
      this.abortController = new AbortController();
      const signal = this.abortController.signal;

      this.discover();

      if ('ResizeObserver' in global) {
        this.resizeObserver = new ResizeObserver(() => {
          this.queueMeasure('resize-observer');
        });
        this.resizeObserver.observe(this.root);

        for (const record of this.records) {
          this.resizeObserver.observe(record.element);
        }
      }

      this.mutationObserver = new MutationObserver((mutations) => {
        let rediscover = false;

        for (const mutation of mutations) {
          if (mutation.type === 'childList') {
            rediscover = true;
            break;
          }

          if (
            mutation.type === 'attributes'
            && mutation.target.matches(this.options.surfaceSelector)
          ) {
            this.queueMeasure('attribute');
          }
        }

        if (rediscover) {
          this.discover();
        }
      });
      this.mutationObserver.observe(this.root, {
        subtree: true,
        childList: true,
        attributes: true,
        attributeFilter: ATTRIBUTE_NAMES,
      });

      global.addEventListener(
        'scroll',
        () => this.queueMeasure('scroll'),
        { passive: true, capture: true, signal }
      );
      this.root.addEventListener(
        'scroll',
        () => this.queueMeasure('root-scroll'),
        { passive: true, capture: true, signal }
      );
      global.addEventListener(
        'resize',
        () => this.queueMeasure('window-resize'),
        { passive: true, signal }
      );
      global.addEventListener(
        'transitionrun',
        () => this.queueMeasure('transition'),
        { passive: true, capture: true, signal }
      );
      global.addEventListener(
        'transitionend',
        () => this.queueMeasure('transition-end'),
        { passive: true, capture: true, signal }
      );
      global.addEventListener(
        'animationstart',
        () => this.queueMeasure('animation'),
        { passive: true, capture: true, signal }
      );
      global.addEventListener(
        'animationiteration',
        () => this.queueMeasure('animation-iteration'),
        { passive: true, capture: true, signal }
      );
    }

    detach() {
      if (this.abortController) {
        this.abortController.abort();
        this.abortController = null;
      }

      if (this.resizeObserver) {
        this.resizeObserver.disconnect();
        this.resizeObserver = null;
      }

      if (this.mutationObserver) {
        this.mutationObserver.disconnect();
        this.mutationObserver = null;
      }
    }

    discover() {
      const elements = Array.from(
        this.root.querySelectorAll(this.options.surfaceSelector)
      );
      const nextRecords = [];
      const currentElements = new Set(elements);

      for (let index = 0; index < elements.length; index += 1) {
        const element = elements[index];
        let record = this.recordMap.get(element);

        if (!record) {
          record = new SurfaceRecord(element, index);
          this.recordMap.set(element, record);

          if (this.resizeObserver) {
            this.resizeObserver.observe(element);
          }
        }

        record.ordinal = index;
        nextRecords.push(record);
      }

      if (this.resizeObserver) {
        for (const record of this.records) {
          if (!currentElements.has(record.element)) {
            this.resizeObserver.unobserve(record.element);
          }
        }
      }

      this.records = nextRecords;
      this.queueMeasure('discover');
      this.signalHub.emit('surfaces-discovered', {
        count: this.records.length,
      });
    }

    queueMeasure(reason) {
      this.measureQueued = true;
      this.lastQueueReason = reason;
    }

    measureIfNeeded(timestamp, force = false) {
      const intervalElapsed = (
        timestamp - this.lastMeasureTime
      ) >= this.options.surfaceMeasureInterval;

      if (!force && !this.measureQueued && !intervalElapsed) {
        return false;
      }

      this.lastMeasureTime = timestamp;
      this.measureQueued = false;
      const viewportHeight = global.innerHeight;
      const visible = [];

      for (const record of this.records) {
        if (record.measure(viewportHeight)) {
          visible.push(record);
        }
      }

      // When more surfaces exist than a uniform block can hold, favor visible
      // interactive controls, then larger surfaces. Stable DOM order remains
      // the final tie-breaker so overlap behavior is predictable.
      if (visible.length > this.options.maxSurfaces) {
        visible.sort((left, right) => {
          const leftInteractive = left.material[2];
          const rightInteractive = right.material[2];

          if (leftInteractive !== rightInteractive) {
            return rightInteractive - leftInteractive;
          }

          const leftArea = left.rect[2] * left.rect[3];
          const rightArea = right.rect[2] * right.rect[3];

          if (leftArea !== rightArea) {
            return rightArea - leftArea;
          }

          return left.ordinal - right.ordinal;
        });
        visible.length = this.options.maxSurfaces;
        visible.sort((left, right) => left.ordinal - right.ordinal);
      }

      this.visibleRecords = visible;
      this.revision += 1;
      this.signalHub.emit('surfaces-measured', {
        count: visible.length,
        total: this.records.length,
        revision: this.revision,
        reason: this.lastQueueReason,
      });
      return true;
    }

    pack() {
      const count = this.visibleRecords.length;
      const rects = new Float32Array(MAX_SURFACES * 4);
      const optics = new Float32Array(MAX_SURFACES * 4);
      const material = new Float32Array(MAX_SURFACES * 4);
      const tint = new Float32Array(MAX_SURFACES * 4);

      for (let index = 0; index < count; index += 1) {
        const offset = index * 4;
        const record = this.visibleRecords[index];
        rects.set(record.rect, offset);
        optics.set(record.optics, offset);
        material.set(record.material, offset);
        tint.set(record.tint, offset);
      }

      return {
        count,
        rects,
        optics,
        material,
        tint,
      };
    }

    snapshots() {
      return this.visibleRecords.map((record) => record.snapshot());
    }
  }

  class FrameGovernor {
    constructor(options, signalHub) {
      this.options = options;
      this.signalHub = signalHub;
      this.samples = new Float32Array(120);
      this.sampleCount = 0;
      this.sampleCursor = 0;
      this.lastEvaluation = 0;
      this.resolutionScale = clamp(
        options.resolutionScale,
        options.minResolutionScale,
        options.maxResolutionScale
      );
      this.quality = clamp(Math.round(options.quality), 0, 1);
      this.averageFrameMs = 0;
      this.p95FrameMs = 0;
      this.framesPerSecond = 0;
      this.degradeVotes = 0;
      this.upgradeVotes = 0;
    }

    addFrame(frameMilliseconds, timestamp) {
      if (!Number.isFinite(frameMilliseconds) || frameMilliseconds <= 0) {
        return;
      }

      this.samples[this.sampleCursor] = frameMilliseconds;
      this.sampleCursor = (this.sampleCursor + 1) % this.samples.length;
      this.sampleCount = Math.min(this.sampleCount + 1, this.samples.length);

      if (timestamp - this.lastEvaluation < 1500) {
        return;
      }

      this.lastEvaluation = timestamp;
      this.evaluate();
    }

    evaluate() {
      if (this.sampleCount < 20) {
        return;
      }

      const currentSamples = Array.from(
        this.samples.slice(0, this.sampleCount)
      ).sort((left, right) => left - right);
      const total = currentSamples.reduce(
        (sum, value) => sum + value,
        0
      );
      this.averageFrameMs = total / currentSamples.length;
      this.p95FrameMs = currentSamples[
        Math.min(
          currentSamples.length - 1,
          Math.floor(currentSamples.length * 0.95)
        )
      ];
      this.framesPerSecond = 1000 / Math.max(this.averageFrameMs, 0.01);

      if (!this.options.autoQuality) {
        return;
      }

      const targetMs = 1000 / this.options.targetFrameRate;
      const tooSlow = this.p95FrameMs > targetMs * 1.42;
      const comfortablyFast = this.p95FrameMs < targetMs * 0.92;

      if (tooSlow) {
        this.degradeVotes += 1;
        this.upgradeVotes = 0;
      } else if (comfortablyFast) {
        this.upgradeVotes += 1;
        this.degradeVotes = 0;
      } else {
        this.degradeVotes = Math.max(0, this.degradeVotes - 1);
        this.upgradeVotes = Math.max(0, this.upgradeVotes - 1);
      }

      if (this.degradeVotes >= 2) {
        this.degrade();
        this.degradeVotes = 0;
      }

      if (this.upgradeVotes >= 5) {
        this.upgrade();
        this.upgradeVotes = 0;
      }
    }

    degrade() {
      const previousScale = this.resolutionScale;
      const previousQuality = this.quality;

      if (this.quality > 0) {
        this.quality -= 1;
      } else {
        this.resolutionScale = clamp(
          this.resolutionScale - 0.08,
          this.options.minResolutionScale,
          this.options.maxResolutionScale
        );
      }

      this.emitChange(previousScale, previousQuality, 'degrade');
    }

    upgrade() {
      const previousScale = this.resolutionScale;
      const previousQuality = this.quality;

      if (this.resolutionScale < this.options.maxResolutionScale) {
        this.resolutionScale = clamp(
          this.resolutionScale + 0.04,
          this.options.minResolutionScale,
          this.options.maxResolutionScale
        );
      } else if (this.quality < 1) {
        this.quality += 1;
      }

      this.emitChange(previousScale, previousQuality, 'upgrade');
    }

    emitChange(previousScale, previousQuality, reason) {
      if (
        previousScale === this.resolutionScale
        && previousQuality === this.quality
      ) {
        return;
      }

      this.signalHub.emit('quality-change', {
        reason,
        resolutionScale: this.resolutionScale,
        quality: this.quality,
        averageFrameMs: this.averageFrameMs,
        p95FrameMs: this.p95FrameMs,
      });
    }

    setQuality(quality, resolutionScale) {
      this.quality = clamp(Math.round(finiteOr(quality, this.quality)), 0, 1);

      if (resolutionScale != null) {
        this.resolutionScale = clamp(
          finiteOr(resolutionScale, this.resolutionScale),
          this.options.minResolutionScale,
          this.options.maxResolutionScale
        );
      }
    }

    snapshot() {
      return {
        quality: this.quality,
        resolutionScale: this.resolutionScale,
        averageFrameMs: this.averageFrameMs,
        p95FrameMs: this.p95FrameMs,
        framesPerSecond: this.framesPerSecond,
        sampleCount: this.sampleCount,
      };
    }
  }

  class WebGLCompositor {
    constructor(canvas, options, signalHub) {
      this.canvas = canvas;
      this.options = options;
      this.signalHub = signalHub;
      this.gl = null;
      this.program = null;
      this.vertexArray = null;
      this.uniforms = new Map();
      this.contextLost = false;
      this.webgl1Available = false;
      this.rendererInfo = null;
      this.lastCssWidth = 0;
      this.lastCssHeight = 0;
      this.lastBufferWidth = 0;
      this.lastBufferHeight = 0;
      this.lastDevicePixelRatio = 1;
      this.abortController = new AbortController();
      this.attachContextEvents();
    }

    attachContextEvents() {
      const signal = this.abortController.signal;

      this.canvas.addEventListener(
        'webglcontextlost',
        (event) => {
          event.preventDefault();
          this.contextLost = true;
          this.program = null;
          this.vertexArray = null;
          document.body.classList.add(BODY_CLASSES.contextLost);
          this.signalHub.emit('context-lost', {
            statusMessage: event.statusMessage || 'WebGL context lost',
          });
          dispatchEngineEvent('context-lost', {
            statusMessage: event.statusMessage || 'WebGL context lost',
          });
        },
        { signal }
      );

      this.canvas.addEventListener(
        'webglcontextrestored',
        () => {
          try {
            this.initializeResources();
            this.contextLost = false;
            document.body.classList.remove(BODY_CLASSES.contextLost);
            this.signalHub.emit('context-restored', {});
            dispatchEngineEvent('context-restored', {});
          } catch (error) {
            this.signalHub.emit('fatal', {
              reason: 'context-restore-failed',
              error,
            });
          }
        },
        { signal }
      );
    }

    createContext() {
      const attributes = {
        alpha: true,
        antialias: false,
        depth: false,
        stencil: false,
        premultipliedAlpha: true,
        preserveDrawingBuffer: false,
        powerPreference: 'low-power',
        desynchronized: true,
        failIfMajorPerformanceCaveat: false,
      };

      this.gl = this.canvas.getContext('webgl2', attributes);

      if (!this.gl) {
        const fallbackCanvas = document.createElement('canvas');
        const webgl1 = fallbackCanvas.getContext('webgl', {
          alpha: true,
          antialias: false,
          powerPreference: 'low-power',
        });
        this.webgl1Available = Boolean(webgl1);

        if (webgl1) {
          const loseContext = webgl1.getExtension('WEBGL_lose_context');
          loseContext?.loseContext();
        }

        return false;
      }

      this.inspectRenderer();
      return true;
    }

    inspectRenderer() {
      const gl = this.gl;
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      this.rendererInfo = {
        vendor: debugInfo
          ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL)
          : gl.getParameter(gl.VENDOR),
        renderer: debugInfo
          ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL)
          : gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxFragmentUniformVectors: gl.getParameter(
          gl.MAX_FRAGMENT_UNIFORM_VECTORS
        ),
      };
    }

    initialize() {
      if (!this.createContext()) {
        return false;
      }

      this.initializeResources();
      return true;
    }

    initializeResources() {
      const gl = this.gl;

      if (!gl) {
        throw new Error('WebGL2 context is unavailable');
      }

      this.disposeResources();

      const vertexShader = this.compileShader(
        gl.VERTEX_SHADER,
        VERTEX_SHADER_SOURCE,
        'vertex'
      );
      const fragmentShader = this.compileShader(
        gl.FRAGMENT_SHADER,
        FRAGMENT_SHADER_SOURCE,
        'fragment'
      );
      this.program = this.linkProgram(vertexShader, fragmentShader);

      gl.deleteShader(vertexShader);
      gl.deleteShader(fragmentShader);

      this.vertexArray = gl.createVertexArray();
      gl.bindVertexArray(this.vertexArray);
      gl.useProgram(this.program);
      gl.disable(gl.DEPTH_TEST);
      gl.disable(gl.CULL_FACE);
      gl.disable(gl.BLEND);
      gl.clearColor(0, 0, 0, 0);

      this.cacheUniformLocations();
    }

    compileShader(type, source, label) {
      const gl = this.gl;
      const shader = gl.createShader(type);

      if (!shader) {
        throw new Error(`Unable to allocate ${label} shader`);
      }

      gl.shaderSource(shader, source);
      gl.compileShader(shader);

      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
        const log = gl.getShaderInfoLog(shader) || 'Unknown shader error';
        gl.deleteShader(shader);
        throw new Error(`${label} shader compilation failed:\n${log}`);
      }

      return shader;
    }

    linkProgram(vertexShader, fragmentShader) {
      const gl = this.gl;
      const program = gl.createProgram();

      if (!program) {
        throw new Error('Unable to allocate WebGL program');
      }

      gl.attachShader(program, vertexShader);
      gl.attachShader(program, fragmentShader);
      gl.linkProgram(program);

      if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
        const log = gl.getProgramInfoLog(program) || 'Unknown link error';
        gl.deleteProgram(program);
        throw new Error(`LiquidGlass shader link failed:\n${log}`);
      }

      return program;
    }

    cacheUniformLocations() {
      const uniformNames = [
        'uResolution',
        'uCssResolution',
        'uMotionTime',
        'uPointer',
        'uPointerMotion',
        'uSurfaceCount',
        'uQuality',
        'uDebug',
        'uAmbientSpeed',
        'uRefractionScale',
        'uDispersionScale',
        'uSpecularScale',
        'uCausticsScale',
        'uFrostScale',
        'uRootBackgroundAlpha',
        'uWindowOptics',
        'uWindowMaterial',
        'uPalette[0]',
        'uSurfaceRects[0]',
        'uSurfaceOptics[0]',
        'uSurfaceMaterial[0]',
        'uSurfaceTint[0]',
      ];

      this.uniforms.clear();

      for (const name of uniformNames) {
        const location = this.gl.getUniformLocation(this.program, name);

        if (location == null) {
          console.warn(`[${ENGINE_NAME}] inactive uniform: ${name}`);
        }

        this.uniforms.set(name, location);
      }
    }

    uniform(name) {
      return this.uniforms.get(name);
    }

    resize(cssWidth, cssHeight, devicePixelRatio, resolutionScale) {
      const gl = this.gl;

      if (!gl || this.contextLost) {
        return false;
      }

      const maxViewport = gl.getParameter(gl.MAX_VIEWPORT_DIMS);
      const maximumWidth = maxViewport[0];
      const maximumHeight = maxViewport[1];
      const effectiveRatio = clamp(
        devicePixelRatio,
        1,
        this.options.maxDevicePixelRatio
      ) * resolutionScale;
      const bufferWidth = clamp(
        Math.round(cssWidth * effectiveRatio),
        1,
        maximumWidth
      );
      const bufferHeight = clamp(
        Math.round(cssHeight * effectiveRatio),
        1,
        maximumHeight
      );

      const changed = this.canvas.width !== bufferWidth
        || this.canvas.height !== bufferHeight;

      if (changed) {
        this.canvas.width = bufferWidth;
        this.canvas.height = bufferHeight;
        gl.viewport(0, 0, bufferWidth, bufferHeight);
      }

      this.lastCssWidth = cssWidth;
      this.lastCssHeight = cssHeight;
      this.lastBufferWidth = bufferWidth;
      this.lastBufferHeight = bufferHeight;
      this.lastDevicePixelRatio = effectiveRatio;
      return changed;
    }

    uploadPalette(palette) {
      const values = new Float32Array(18);
      const ordered = [
        palette.midnight,
        palette.navy,
        palette.cobalt,
        palette.violet,
        palette.cyan,
        palette.mint,
      ];

      for (let index = 0; index < ordered.length; index += 1) {
        const color = ordered[index];
        values[index * 3] = color[0];
        values[index * 3 + 1] = color[1];
        values[index * 3 + 2] = color[2];
      }

      this.gl.uniform3fv(this.uniform('uPalette[0]'), values);
    }

    render(frame) {
      const gl = this.gl;

      if (
        !gl
        || !this.program
        || !this.vertexArray
        || this.contextLost
      ) {
        return false;
      }

      gl.useProgram(this.program);
      gl.bindVertexArray(this.vertexArray);

      gl.uniform2f(
        this.uniform('uResolution'),
        this.canvas.width,
        this.canvas.height
      );
      gl.uniform2f(
        this.uniform('uCssResolution'),
        frame.cssWidth,
        frame.cssHeight
      );
      gl.uniform1f(this.uniform('uMotionTime'), frame.motionTime);
      gl.uniform4fv(this.uniform('uPointer'), frame.pointer);
      gl.uniform4fv(this.uniform('uPointerMotion'), frame.pointerMotion);
      gl.uniform1i(this.uniform('uSurfaceCount'), frame.surfaces.count);
      gl.uniform1i(this.uniform('uQuality'), frame.quality);
      gl.uniform1i(this.uniform('uDebug'), frame.debug);
      gl.uniform1f(
        this.uniform('uAmbientSpeed'),
        this.options.ambientSpeed
      );
      gl.uniform1f(
        this.uniform('uRefractionScale'),
        this.options.refractionScale
      );
      gl.uniform1f(
        this.uniform('uDispersionScale'),
        this.options.dispersionScale
      );
      gl.uniform1f(
        this.uniform('uSpecularScale'),
        this.options.specularScale
      );
      gl.uniform1f(
        this.uniform('uCausticsScale'),
        this.options.causticsScale
      );
      gl.uniform1f(
        this.uniform('uFrostScale'),
        this.options.frostScale
      );
      gl.uniform1f(
        this.uniform('uRootBackgroundAlpha'),
        this.options.rootBackgroundAlpha
      );
      gl.uniform4f(
        this.uniform('uWindowOptics'),
        this.options.windowCornerRadius,
        this.options.windowDepth,
        this.options.windowRefraction,
        this.options.windowDispersion
      );
      gl.uniform4f(
        this.uniform('uWindowMaterial'),
        this.options.windowSpecular,
        this.options.windowCaustics,
        0,
        0
      );

      this.uploadPalette(this.options.palette);
      gl.uniform4fv(
        this.uniform('uSurfaceRects[0]'),
        frame.surfaces.rects
      );
      gl.uniform4fv(
        this.uniform('uSurfaceOptics[0]'),
        frame.surfaces.optics
      );
      gl.uniform4fv(
        this.uniform('uSurfaceMaterial[0]'),
        frame.surfaces.material
      );
      gl.uniform4fv(
        this.uniform('uSurfaceTint[0]'),
        frame.surfaces.tint
      );

      gl.drawArrays(gl.TRIANGLES, 0, 3);
      return true;
    }

    disposeResources() {
      const gl = this.gl;

      if (!gl) {
        return;
      }

      if (this.vertexArray) {
        gl.deleteVertexArray(this.vertexArray);
        this.vertexArray = null;
      }

      if (this.program) {
        gl.deleteProgram(this.program);
        this.program = null;
      }

      this.uniforms.clear();
    }

    loseContext() {
      const extension = this.gl?.getExtension('WEBGL_lose_context');
      extension?.loseContext();
      return Boolean(extension);
    }

    restoreContext() {
      const extension = this.gl?.getExtension('WEBGL_lose_context');
      extension?.restoreContext();
      return Boolean(extension);
    }

    dispose() {
      this.abortController.abort();
      this.disposeResources();

      if (this.gl && !this.contextLost) {
        const extension = this.gl.getExtension('WEBGL_lose_context');
        extension?.loseContext();
      }

      this.gl = null;
    }

    snapshot() {
      return {
        contextLost: this.contextLost,
        webgl1Available: this.webgl1Available,
        rendererInfo: this.rendererInfo,
        cssSize: [this.lastCssWidth, this.lastCssHeight],
        bufferSize: [this.lastBufferWidth, this.lastBufferHeight],
        effectivePixelRatio: this.lastDevicePixelRatio,
      };
    }
  }

  class LiquidGlassEngine {
    constructor(options = {}) {
      this.options = mergeOptions(DEFAULT_OPTIONS, options);
      this.signalHub = new SignalHub();
      this.root = null;
      this.canvas = null;
      this.compositor = null;
      this.surfaceRegistry = null;
      this.pointer = new PointerState(this.options);
      this.governor = new FrameGovernor(this.options, this.signalHub);
      this.resizeObserver = null;
      this.motionQuery = null;
      this.abortController = null;
      this.animationFrame = 0;
      this.running = false;
      this.paused = false;
      this.destroyed = false;
      this.reducedMotion = false;
      this.lastFrameTimestamp = 0;
      this.lastRafTimestamp = 0;
      this.startTimestamp = 0;
      this.motionTime = 0;
      this.lastRenderedTimestamp = 0;
      this.nextRenderTimestamp = 0;
      this.lastTargetFrameRate = 0;
      this.activeUntil = 0;
      this.lastActivityReason = 'startup';
      this.debugMode = this.options.debug ? 1 : 0;
      this.frameCount = 0;
      this.renderedFrameCount = 0;
      this.skippedFrameCount = 0;
      this.fallbackReason = null;
      this.surfacePack = {
        count: 0,
        rects: new Float32Array(MAX_SURFACES * 4),
        optics: new Float32Array(MAX_SURFACES * 4),
        material: new Float32Array(MAX_SURFACES * 4),
        tint: new Float32Array(MAX_SURFACES * 4),
      };

      this.handleFrame = this.handleFrame.bind(this);
      this.handleVisibility = this.handleVisibility.bind(this);
      this.handleMotionPreference = this.handleMotionPreference.bind(this);
      this.markActivity = this.markActivity.bind(this);
    }

    resolveRoot() {
      const requested = document.querySelector(this.options.rootSelector);
      return requested || document.body;
    }

    createCanvas() {
      const existing = document.getElementById(CANVAS_ID);

      if (existing) {
        existing.remove();
      }

      const canvas = document.createElement('canvas');
      canvas.id = CANVAS_ID;
      canvas.setAttribute('aria-hidden', 'true');
      canvas.setAttribute('role', 'presentation');
      canvas.tabIndex = -1;
      this.root.prepend(canvas);
      return canvas;
    }

    injectRuntimeStyles() {
      if (document.getElementById(STYLE_ID)) {
        return;
      }

      const style = document.createElement('style');
      style.id = STYLE_ID;
      style.textContent = `
        [data-liquidglass-root] {
          position: relative;
          isolation: isolate;
          background: transparent !important;
        }

        #${CANVAS_ID} {
          position: absolute;
          inset: 0;
          z-index: 1;
          display: block;
          width: 100%;
          height: 100%;
          pointer-events: none;
          contain: strict;
        }

        body[data-liquidglass-root] > #${CANVAS_ID} {
          position: fixed;
        }

        body.${BODY_CLASSES.ready} ${SURFACE_SELECTOR} {
          background-color: transparent;
          background-image: none;
          -webkit-backdrop-filter: none;
          backdrop-filter: none;
        }

        body.${BODY_CLASSES.fallback} ${SURFACE_SELECTOR} {
          border: 1px solid rgba(230, 244, 255, 0.26);
          background:
            linear-gradient(
              135deg,
              rgba(255, 255, 255, 0.18),
              rgba(255, 255, 255, 0.06)
            );
          box-shadow:
            inset 0 1px rgba(255, 255, 255, 0.36),
            0 18px 48px rgba(2, 9, 28, 0.22);
          -webkit-backdrop-filter: blur(24px) saturate(150%);
          backdrop-filter: blur(24px) saturate(150%);
        }

        body.${BODY_CLASSES.contextLost} #${CANVAS_ID} {
          opacity: 0;
        }

        @media (prefers-reduced-motion: reduce) {
          #${CANVAS_ID} {
            animation: none !important;
          }
        }
      `;
      document.head.append(style);
    }

    attachLifecycle() {
      this.abortController = new AbortController();
      const signal = this.abortController.signal;

      document.addEventListener(
        'visibilitychange',
        this.handleVisibility,
        { signal }
      );
      global.addEventListener(
        'pageshow',
        () => this.resume('pageshow'),
        { signal }
      );
      global.addEventListener(
        'pagehide',
        () => this.pause('pagehide'),
        { signal }
      );
      this.root.addEventListener(
        'pointermove',
        () => this.markActivity('pointer'),
        { passive: true, signal }
      );
      this.root.addEventListener(
        'pointerdown',
        () => this.markActivity('pointer-down'),
        { passive: true, signal }
      );
      this.root.addEventListener(
        'wheel',
        () => this.markActivity('wheel'),
        { passive: true, capture: true, signal }
      );
      this.root.addEventListener(
        'scroll',
        () => this.markActivity('scroll'),
        { passive: true, capture: true, signal }
      );
      this.root.addEventListener(
        'keydown',
        () => this.markActivity('keyboard'),
        { passive: true, capture: true, signal }
      );

      this.motionQuery = global.matchMedia(
        '(prefers-reduced-motion: reduce)'
      );
      this.motionQuery.addEventListener(
        'change',
        this.handleMotionPreference,
        { signal }
      );
      this.handleMotionPreference(this.motionQuery);

      if ('ResizeObserver' in global) {
        this.resizeObserver = new ResizeObserver(() => {
          this.surfaceRegistry?.queueMeasure('engine-root-resize');
          this.markActivity('resize');
          this.resizeCanvas(true);
        });
        this.resizeObserver.observe(this.root);
      }

      this.signalHub.on('quality-change', (detail) => {
        this.resizeCanvas(true);
        dispatchEngineEvent('quality-change', detail);
      });

      this.signalHub.on('fatal', ({ reason, error }) => {
        console.error(`[${ENGINE_NAME}] ${reason}`, error);
        this.enterFallback(reason, error);
      });
    }

    handleVisibility() {
      if (!this.options.pauseWhenHidden) {
        return;
      }

      if (document.hidden) {
        this.pause('document-hidden');
      } else {
        this.resume('document-visible');
      }
    }

    handleMotionPreference(event) {
      if (this.options.reducedMotion === true) {
        this.reducedMotion = true;
      } else if (this.options.reducedMotion === false) {
        this.reducedMotion = false;
      } else {
        this.reducedMotion = Boolean(event.matches);
      }

      document.body.classList.toggle(
        BODY_CLASSES.reducedMotion,
        this.reducedMotion
      );
      dispatchEngineEvent('motion-preference', {
        reducedMotion: this.reducedMotion,
      });
    }

    start() {
      if (this.running) {
        return true;
      }

      if (this.destroyed) {
        throw new Error('A destroyed LiquidGlass engine cannot be restarted');
      }

      this.root = this.resolveRoot();
      this.root.setAttribute('data-liquidglass-root', '');
      this.injectRuntimeStyles();
      this.canvas = this.createCanvas();
      this.compositor = new WebGLCompositor(
        this.canvas,
        this.options,
        this.signalHub
      );

      if (!this.compositor.initialize()) {
        this.enterFallback(
          'webgl2-unavailable',
          null,
          this.compositor.webgl1Available
        );
        return false;
      }

      this.surfaceRegistry = new SurfaceRegistry(
        this.root,
        this.options,
        this.signalHub
      );
      this.surfaceRegistry.attach();
      this.pointer.attach(this.root);
      this.attachLifecycle();

      this.running = true;
      this.paused = false;
      this.startTimestamp = global.performance.now();
      this.lastFrameTimestamp = this.startTimestamp;
      this.lastRafTimestamp = this.startTimestamp;
      this.lastRenderedTimestamp = 0;
      this.nextRenderTimestamp = 0;
      this.lastTargetFrameRate = 0;
      this.markActivity('startup');
      this.resizeCanvas(true);
      this.surfaceRegistry.measureIfNeeded(this.startTimestamp, true);
      this.surfacePack = this.surfaceRegistry.pack();

      document.body.classList.remove(BODY_CLASSES.fallback);
      document.body.classList.add(BODY_CLASSES.ready);
      document.body.classList.toggle(
        BODY_CLASSES.debug,
        this.debugMode > 0
      );

      this.animationFrame = global.requestAnimationFrame(this.handleFrame);
      const detail = {
        version: ENGINE_VERSION,
        surfaceCount: this.surfacePack.count,
        renderer: this.compositor.rendererInfo,
      };
      this.signalHub.emit('ready', detail);
      dispatchEngineEvent('ready', detail);
      return true;
    }

    shouldRender(timestamp) {
      if (this.paused || !this.running || this.compositor?.contextLost) {
        return false;
      }

      const activelyChanging = timestamp <= this.activeUntil
        || this.pointer.down;
      const targetRate = activelyChanging && !this.reducedMotion
        ? this.options.targetFrameRate
        : this.options.idleFrameRate;
      const interval = 1000 / Math.max(targetRate, 1);

      if (targetRate !== this.lastTargetFrameRate) {
        this.lastTargetFrameRate = targetRate;
        this.nextRenderTimestamp = timestamp;
      }

      if (timestamp + 0.5 < this.nextRenderTimestamp) {
        return false;
      }

      this.nextRenderTimestamp += interval;

      if (this.nextRenderTimestamp < timestamp - interval) {
        this.nextRenderTimestamp = timestamp + interval;
      }

      return true;
    }

    markActivity(reason = 'external') {
      const timestamp = global.performance.now();
      this.activeUntil = Math.max(
        this.activeUntil,
        timestamp + this.options.idleDelay
      );
      this.lastActivityReason = reason;
    }

    handleFrame(timestamp) {
      if (!this.running) {
        return;
      }

      this.animationFrame = global.requestAnimationFrame(this.handleFrame);
      this.frameCount += 1;

      const rafMilliseconds = this.lastRafTimestamp > 0
        ? timestamp - this.lastRafTimestamp
        : 1000 / 60;
      this.lastRafTimestamp = timestamp;

      if (!this.shouldRender(timestamp)) {
        this.skippedFrameCount += 1;
        return;
      }

      const frameStart = global.performance.now();
      const deltaSeconds = clamp(
        (timestamp - this.lastFrameTimestamp) * 0.001,
        0,
        this.options.maxFrameDelta
      );
      this.lastFrameTimestamp = timestamp;
      this.lastRenderedTimestamp = timestamp;

      const activelyChanging = timestamp <= this.activeUntil
        || this.pointer.down;
      const motionMultiplier = this.reducedMotion || !activelyChanging
        ? 0
        : 1;
      this.motionTime += deltaSeconds * motionMultiplier;
      this.pointer.tick(deltaSeconds);

      const surfacesChanged = this.surfaceRegistry.measureIfNeeded(timestamp);

      if (surfacesChanged) {
        this.surfacePack = this.surfaceRegistry.pack();
      }

      this.resizeCanvas(false);

      const rendered = this.compositor.render({
        cssWidth: this.compositor.lastCssWidth,
        cssHeight: this.compositor.lastCssHeight,
        time: (timestamp - this.startTimestamp) * 0.001,
        motionTime: this.motionTime,
        deltaSeconds,
        resolutionScale: this.governor.resolutionScale,
        quality: this.governor.quality,
        debug: this.debugMode,
        pointer: this.pointer.toUniform(),
        pointerMotion: this.pointer.motionUniform(),
        surfaces: this.surfacePack,
      });

      if (rendered) {
        this.renderedFrameCount += 1;
      }

      const frameMilliseconds = global.performance.now() - frameStart;
      if (!this.reducedMotion) {
        // GPU submission is asynchronous, so CPU render duration alone can
        // look deceptively cheap. RAF cadence captures GPU/compositor pressure
        // while the CPU duration catches JavaScript or uniform-upload spikes.
        this.governor.addFrame(
          Math.max(frameMilliseconds, rafMilliseconds),
          timestamp
        );
      }
    }

    resizeCanvas(force) {
      if (!this.compositor || !this.root) {
        return false;
      }

      const rect = this.root.getBoundingClientRect();
      const cssWidth = Math.max(1, rect.width || global.innerWidth);
      const cssHeight = Math.max(1, rect.height || global.innerHeight);
      const devicePixelRatio = finiteOr(global.devicePixelRatio, 1);

      const needsResize = force
        || cssWidth !== this.compositor.lastCssWidth
        || cssHeight !== this.compositor.lastCssHeight
        || devicePixelRatio !== this.lastObservedDevicePixelRatio;

      if (!needsResize) {
        return false;
      }

      this.lastObservedDevicePixelRatio = devicePixelRatio;
      const changed = this.compositor.resize(
        cssWidth,
        cssHeight,
        devicePixelRatio,
        this.governor.resolutionScale
      );
      this.surfaceRegistry?.queueMeasure('canvas-resize');
      return changed;
    }

    pause(reason = 'manual') {
      if (!this.running || this.paused) {
        return;
      }

      this.paused = true;
      document.body.classList.add(BODY_CLASSES.paused);
      this.signalHub.emit('paused', { reason });
      dispatchEngineEvent('paused', { reason });
    }

    resume(reason = 'manual') {
      if (!this.running || !this.paused) {
        return;
      }

      this.paused = false;
      this.lastFrameTimestamp = global.performance.now();
      this.markActivity(`resume:${reason}`);
      document.body.classList.remove(BODY_CLASSES.paused);
      this.surfaceRegistry?.queueMeasure('resume');
      this.signalHub.emit('resumed', { reason });
      dispatchEngineEvent('resumed', { reason });
    }

    refresh() {
      this.markActivity('refresh');
      this.surfaceRegistry?.discover();
      this.surfaceRegistry?.measureIfNeeded(
        global.performance.now(),
        true
      );

      if (this.surfaceRegistry) {
        this.surfacePack = this.surfaceRegistry.pack();
      }

      this.resizeCanvas(true);
      return this.surfacePack.count;
    }

    setDebug(mode) {
      if (mode === true) {
        this.debugMode = 1;
      } else if (mode === false) {
        this.debugMode = 0;
      } else {
        this.debugMode = clamp(Math.round(finiteOr(mode, 0)), 0, 4);
      }

      document.body.classList.toggle(
        BODY_CLASSES.debug,
        this.debugMode > 0
      );
      return this.debugMode;
    }

    setQuality(quality, resolutionScale) {
      this.governor.setQuality(quality, resolutionScale);
      this.markActivity('quality-change');
      this.resizeCanvas(true);
      return this.governor.snapshot();
    }

    setOptions(nextOptions) {
      if (!nextOptions || typeof nextOptions !== 'object') {
        return this.options;
      }

      const previousRootSelector = this.options.rootSelector;
      const previousSurfaceSelector = this.options.surfaceSelector;
      this.options = mergeOptions(this.options, nextOptions);
      this.pointer.options = this.options;
      this.governor.options = this.options;

      if (this.compositor) {
        this.compositor.options = this.options;
      }

      if (this.surfaceRegistry) {
        this.surfaceRegistry.options = this.options;
      }

      if (
        previousRootSelector !== this.options.rootSelector
        || previousSurfaceSelector !== this.options.surfaceSelector
      ) {
        console.warn(
          `[${ENGINE_NAME}] selector changes require recreate()`
        );
      }

      this.resizeCanvas(true);
      this.refresh();
      return this.options;
    }

    enterFallback(reason, error = null, webgl1Available = false) {
      this.fallbackReason = reason;
      this.running = false;

      if (this.animationFrame) {
        global.cancelAnimationFrame(this.animationFrame);
        this.animationFrame = 0;
      }

      if (this.canvas) {
        this.canvas.hidden = true;
      }

      document.body.classList.remove(BODY_CLASSES.ready);
      document.body.classList.add(BODY_CLASSES.fallback);
      document.body.classList.toggle(BODY_CLASSES.webgl1, webgl1Available);

      const detail = {
        reason,
        error: error ? String(error.message || error) : null,
        webgl1Available,
      };
      this.signalHub.emit('fallback', detail);
      dispatchEngineEvent('fallback', detail);
      console.warn(`[${ENGINE_NAME}] CSS fallback enabled: ${reason}`, error || '');
    }

    on(name, listener) {
      return this.signalHub.on(name, listener);
    }

    inspect() {
      return {
        engine: {
          name: ENGINE_NAME,
          version: ENGINE_VERSION,
          running: this.running,
          paused: this.paused,
          destroyed: this.destroyed,
          reducedMotion: this.reducedMotion,
          debugMode: this.debugMode,
          fallbackReason: this.fallbackReason,
          activeUntil: this.activeUntil,
          lastActivityReason: this.lastActivityReason,
        },
        frames: {
          requested: this.frameCount,
          rendered: this.renderedFrameCount,
          skipped: this.skippedFrameCount,
        },
        performance: this.governor.snapshot(),
        compositor: this.compositor?.snapshot() || null,
        surfaces: this.surfaceRegistry?.snapshots() || [],
        options: Object.assign({}, this.options, {
          palette: Object.assign({}, this.options.palette),
        }),
      };
    }

    destroy() {
      if (this.destroyed) {
        return;
      }

      this.running = false;
      this.paused = false;
      this.destroyed = true;

      if (this.animationFrame) {
        global.cancelAnimationFrame(this.animationFrame);
        this.animationFrame = 0;
      }

      this.abortController?.abort();
      this.abortController = null;
      this.resizeObserver?.disconnect();
      this.resizeObserver = null;
      this.pointer.detach();
      this.surfaceRegistry?.detach();
      this.surfaceRegistry = null;
      this.compositor?.dispose();
      this.compositor = null;
      this.canvas?.remove();
      this.canvas = null;
      this.root?.removeAttribute('data-liquidglass-root');
      this.root = null;

      document.body.classList.remove(
        BODY_CLASSES.ready,
        BODY_CLASSES.fallback,
        BODY_CLASSES.webgl1,
        BODY_CLASSES.paused,
        BODY_CLASSES.reducedMotion,
        BODY_CLASSES.contextLost,
        BODY_CLASSES.debug
      );

      this.signalHub.emit('destroyed', {});
      dispatchEngineEvent('destroyed', {});
      this.signalHub.clear();
    }
  }

  let activeEngine = null;

  function createDebugApi() {
    return Object.freeze({
      get version() {
        return ENGINE_VERSION;
      },

      get engine() {
        return activeEngine;
      },

      start(options) {
        if (activeEngine && !activeEngine.destroyed) {
          return activeEngine.start();
        }

        activeEngine = new LiquidGlassEngine(options);
        return activeEngine.start();
      },

      stop() {
        activeEngine?.destroy();
        activeEngine = null;
      },

      recreate(options) {
        activeEngine?.destroy();
        activeEngine = new LiquidGlassEngine(options);
        return activeEngine.start();
      },

      pause(reason) {
        activeEngine?.pause(reason || 'debug-api');
      },

      resume(reason) {
        activeEngine?.resume(reason || 'debug-api');
      },

      refresh() {
        return activeEngine?.refresh() || 0;
      },

      inspect() {
        return activeEngine?.inspect() || null;
      },

      surfaces() {
        return activeEngine?.surfaceRegistry?.snapshots() || [];
      },

      setDebug(mode) {
        return activeEngine?.setDebug(mode) || 0;
      },

      setQuality(quality, resolutionScale) {
        return activeEngine?.setQuality(quality, resolutionScale) || null;
      },

      setOptions(options) {
        return activeEngine?.setOptions(options) || null;
      },

      loseContext() {
        return activeEngine?.compositor?.loseContext() || false;
      },

      restoreContext() {
        return activeEngine?.compositor?.restoreContext() || false;
      },

      on(name, listener) {
        return activeEngine?.on(name, listener) || (() => {});
      },

      help() {
        return {
          selector: SURFACE_SELECTOR,
          attributes: ATTRIBUTE_NAMES.slice(),
          debugModes: {
            0: 'normal rendering',
            1: 'surface identity and boundaries',
            2: 'edge, Fresnel, and displacement channels',
            3: 'surface normals',
            4: 'full-window optical normals',
          },
          examples: [
            'NeutronLiquidGlass.inspect()',
            'NeutronLiquidGlass.setDebug(1)',
            'NeutronLiquidGlass.setQuality(2, 1)',
            'NeutronLiquidGlass.refresh()',
            'NeutronLiquidGlass.loseContext()',
            'NeutronLiquidGlass.recreate({ autoQuality: false })',
          ],
        };
      },
    });
  }

  const debugApi = createDebugApi();

  Object.defineProperty(global, 'NeutronLiquidGlass', {
    value: debugApi,
    writable: false,
    configurable: true,
    enumerable: true,
  });

  function autoStart() {
    if (document.documentElement.hasAttribute('data-liquidglass-manual')) {
      return;
    }

    try {
      activeEngine = new LiquidGlassEngine();
      activeEngine.start();
    } catch (error) {
      console.error(`[${ENGINE_NAME}] startup failed`, error);
      document.body.classList.remove(BODY_CLASSES.ready);
      document.body.classList.add(BODY_CLASSES.fallback);
      dispatchEngineEvent('fallback', {
        reason: 'startup-exception',
        error: String(error.message || error),
        webgl1Available: false,
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoStart, { once: true });
  } else {
    autoStart();
  }
})(window);

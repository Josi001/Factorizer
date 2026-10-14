# ============================================================================
#  DJANGO REST FRAMEWORK VIEWS (api/views.py)
# ============================================================================

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view

from utils.rsa_utils import RSAKeyGenerator
from utils.rsa_crypto import RSACrypto
from utils.strength_analyzer import StrengthAnalyzer


class GenerateKeysView(APIView):
    """
    POST /api/generate-keys/

    Body:
    {
        "prime_type": "standard|small|large|close|widely_spaced|equal",
        "bits": 512  // optional, default 512
    }
    """

    def post(self, request):
        prime_type = request.data.get('prime_type', 'standard')
        bits = request.data.get('bits', 512)

        try:
            keys = RSAKeyGenerator.generate_by_type(prime_type, bits)

            return Response({
                'success': True,
                'keys': {
                    'public_key': keys['public_key'],
                    'private_key': keys['private_key'],
                    'primes': keys['primes'],
                    'metadata': keys['metadata']
                },
                'prime_type': prime_type
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class AnalyzeStrengthView(APIView):
    """
    POST /api/analyze-strength/

    Body:
    {
        "public_key": {"n": ..., "e": ...},
        "private_key": {"n": ..., "d": ...},
        "primes": {"p": ..., "q": ...},
        "metadata": {...},
        "test_message": "optional custom message"
    }
    """

    def post(self, request):
        try:
            keys = {
                'public_key': request.data.get('public_key'),
                'private_key': request.data.get('private_key'),
                'primes': request.data.get('primes'),
                'metadata': request.data.get('metadata')
            }

            test_message = request.data.get('test_message', 'Test Message')

            analysis = StrengthAnalyzer.analyze_key_strength(keys, test_message)

            return Response({
                'success': True,
                'analysis': analysis
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class EncryptView(APIView):
    """
    POST /api/encrypt/

    Body:
    {
        "message": "text to encrypt",
        "public_key": {"n": ..., "e": ...}
    }
    """

    def post(self, request):
        try:
            message = request.data.get('message')
            public_key = request.data.get('public_key')

            ciphertext = RSACrypto.encrypt(message, public_key)

            return Response({
                'success': True,
                'ciphertext': str(ciphertext),
                'message_length': len(message)
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


class DecryptView(APIView):
    """
    POST /api/decrypt/

    Body:
    {
        "ciphertext": "encrypted text as string",
        "private_key": {"n": ..., "d": ...}
    }
    """

    def post(self, request):
        try:
            ciphertext = int(request.data.get('ciphertext'))
            private_key = request.data.get('private_key')

            decrypted_message = RSACrypto.decrypt(ciphertext, private_key)

            return Response({
                'success': True,
                'message': decrypted_message
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def generate_and_analyze(request):
    """
    POST /api/generate-and-analyze/

    Convenience endpoint that generates keys and analyzes them in one call.

    Body:
    {
        "prime_type": "standard|small|large|close|widely_spaced|equal",
        "bits": 512,
        "test_message": "optional"
    }
    """
    try:
        prime_type = request.data.get('prime_type', 'standard')
        bits = request.data.get('bits', 512)
        test_message = request.data.get('test_message', 'Test Message')

        # Generate keys
        keys = RSAKeyGenerator.generate_by_type(prime_type, bits)

        # Analyze strength
        analysis = StrengthAnalyzer.analyze_key_strength(keys, test_message)

        return Response({
            'success': True,
            'prime_type': prime_type,
            'keys': keys,
            'analysis': analysis
        }, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({
            'success': False,
            'error': str(e)
        }, status=status.HTTP_400_BAD_REQUEST)


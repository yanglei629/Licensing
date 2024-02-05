from collections import deque
from xml.etree.ElementTree import ElementTree, SubElement, Element, parse, fromstring, tostring
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from base64 import b64encode, b64decode
from datetime import datetime, timedelta


class LisenseBuilder:
    def __init__(self):
        self.license = License()

    def with_unique_identifier(self, license_id):
        return self

    def as_(self, license_type):
        return self

    def with_maximum_utilization(self, utilization):
        return self

    def expires_at(self, date):
        self.license.expiration = date
        return self

    def licensed_to(self, name, email):
        self.license.customer.name = name
        self.license.customer.email = email
        return self

    def with_product_features(self, product_features):
        self.license.product_features.add_all(product_features)
        return self

    def create_and_sign_with_private_key(self, private_key, pass_phrase):
        self.license.sign(private_key, pass_phrase)
        return self.license


class ValidationFailure:
    def __init__(self, message, how_to_resolve):
        self._message = message
        self._how_to_resolve = how_to_resolve

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, value):
        self._message = value

    @property
    def how_to_resolve(self):
        return self._how_to_resolve

    @how_to_resolve.setter
    def how_to_resolve(self, value):
        self._how_to_resolve = value


class GeneralValidationFailure(Exception):
    def __init__(self, message):
        self.message = message
        super().__init__(message)


class LicenseValidator:
    def __init__(self):
        self.validate = None
        self.validate_when = None
        self.failure_result = None


class LicenseValidatorBuilder:
    def __init__(self, license):
        self.license = license
        self.current_validator_chain = None
        self.validators = deque()

    def start_validator_chain(self):
        pass
        # self.current_validator_chain = LicenseValidator()
        # return self.current_validator_chain

    def complete_validator_chain(self):
        if self.current_validator_chain is not None:
            self.validators.append(self.current_validator_chain)
            # self.current_validator_chain = None

    def expiration_date(self):
        validator = LicenseValidator()
        self.current_validator_chain = validator
        self.start_validator_chain()

        validator.validate = lambda license: license['expiration'] > datetime.now()

        validator.failure_result = ValidationFailure()
        validator.failure_result.message = "Licensing for this product has expired!"
        validator.failure_result.how_to_resolve = "Your license is expired. Please contact your distributor/vendor to renew the license."

        return self

    def assert_that(self, predicate, failure):
        validator = LicenseValidator()
        self.current_validator_chain = validator
        self.start_validator_chain()

        validator.validate = predicate
        validator.failure_result = failure

        return self

    def and_(self):
        self.complete_validator_chain()
        return self

    def signature(self, public_key):
        # 这里可能是签名操作的实现
        verify_result = self.license.verify_signature(public_key)
        print(verify_result)
        return self

    def assert_valid_license(self):
        self.complete_validator_chain()

        print(f"deque size:{len(self.validators)}")
        while self.validators:
            validator = self.validators.popleft()
            if validator.validate_when and not validator.validate_when(self.license):
                continue

            if callable(validator.validate) and not validator.validate(self.license):
                yield validator.failure_result or GeneralValidationFailure("License validation failed!")


class LicenseAttributes:
    def __init__(self, xml_data, child_name):
        self.xml_data = xml_data if xml_data is not None else Element("null")
        self.child_name = child_name

    def add(self, key, value):
        self.set_child_tag(key, value)

    def add_all(self, features):
        for feature_key, feature_value in features.items():
            self.add(feature_key, feature_value)

    def remove(self, key):
        element = next((e for e in self.xml_data.findall(self.child_name)
                        if e.get("name") is not None and e.get("name") == key), None)

        if element is not None:
            self.xml_data.remove(element)

    def remove_all(self):
        self.xml_data.clear()

    def get(self, key):
        return self.get_child_tag(key)

    def get_all(self):
        return {e.get("name"): e.text for e in self.xml_data.findall(self.child_name)}

    def contains(self, key):
        return any(e.get("name") == key for e in self.xml_data.findall(self.child_name))

    def contains_all(self, keys):
        return all(e.get("name") in keys for e in self.xml_data.findall(self.child_name))

    def set_tag(self, name, value):
        element = self.xml_data.find(name)

        if element is None:
            element = SubElement(self.xml_data, name)

        if value is not None:
            element.text = value

    def set_child_tag(self, name, value):
        element = next((e for e in self.xml_data.findall(self.child_name)
                        if e.get("name") is not None and e.get("name") == name), None)

        if element is None:
            element = SubElement(self.xml_data, self.child_name)
            element.set("name", name)

        if value is not None:
            element.text = value

    def get_tag(self, name):
        element = self.xml_data.find(name)
        return element.text if element is not None else None

    def get_child_tag(self, name):
        element = next((e for e in self.xml_data.findall(self.child_name)
                        if e.get("name") is not None and e.get("name") == name), None)

        return element.text if element is not None else None


class Customer(LicenseAttributes):
    def __init__(self, xml_data: Element):
        super().__init__(xml_data, "CustomerData")

    @property
    def name(self):
        return self.get_tag("Name")

    @name.setter
    def name(self, value):
        self.set_tag("Name", value)

    @property
    def company(self):
        return self.get_tag("Company")

    @company.setter
    def company(self, value):
        self.set_tag("Company", value)

    @property
    def email(self):
        return self.get_tag("Email")

    @email.setter
    def email(self, value):
        self.set_tag("Email", value)


class License:
    def __init__(self, xml_data=None):
        if xml_data is None:
            self.xml_data = Element("License")
        else:
            self.xml_data = xml_data

    @property
    def is_signed(self):
        return bool(self.get_tag("Signature"))

    @property
    def customer(self):
        xml_element = self.xml_data.find("Customer")

        if not self.is_signed and xml_element is None:
            self.xml_data.append(Element("Customer"))
            xml_element = self.xml_data.find("Customer")
        elif self.is_signed and xml_element is None:
            return None

        return Customer(xml_element)

    @property
    def expiration(self):
        expiration_tag = self.get_tag("Expiration")
        default_expiration = (datetime.utcnow() + timedelta(days=365)).strftime("%a, %d %b %Y %H:%M:%S GMT")

        return datetime.strptime(expiration_tag, "%a, %d %b %Y %H:%M:%S GMT") if expiration_tag else datetime.strptime(
            default_expiration, "%a, %d %b %Y %H:%M:%S GMT")

    @expiration.setter
    def expiration(self, value):
        if not self.is_signed:
            self.set_tag("Expiration", value.strftime("%a, %d %b %Y %H:%M:%S GMT"))

    @property
    def product_features(self):
        xml_element = self.xml_data.find("ProductFeatures")

        if not self.is_signed and xml_element is None:
            self.xml_data.append(Element("ProductFeatures"))
            xml_element = self.xml_data.find("ProductFeatures")
        elif self.is_signed and xml_element is None:
            return None

        return LicenseAttributes(xml_element, "Feature")

    @staticmethod
    def new():
        return LisenseBuilder()

    def validate(self):
        return LicenseValidatorBuilder(self)

    def set_tag(self, name, value):
        element = self.xml_data.find(name)

        if element is None:
            element = SubElement(self.xml_data, name)
            element.text = value

        if value is not None:
            element.text = value

    def get_tag(self, name):
        element = self.xml_data.find(name)
        element = element.text if element is not None else None
        return element

    @staticmethod
    def load_from_file(file):
        tree = parse(file)
        return License(xml_data=tree.getroot())

    @staticmethod
    def load_from_xml_string(xml_string):
        return License(xml_data=fromstring(xml_string))

    def sign_message(self, private_key, message):
        key = RSA.import_key(private_key)
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        return b64encode(signature).decode('utf-8')

    def sign(self, private_key, passPhrase):
        # 对消息进行签名
        signature = self.sign_message(private_key, tostring(self.xml_data, encoding='unicode'))
        self.set_tag("Signature", signature)
        print(f"Signature: {signature}")

    def verify_signature(self, public_key):
        sign_tag = self.xml_data.find("Signature")

        if sign_tag is None:
            return False

        try:
            self.xml_data.remove(sign_tag)

            pub_key = RSA.import_key(public_key)

            document_to_sign = tostring(self.xml_data, encoding="utf-8", method="xml")
            document_hash = SHA256.new(document_to_sign)

            verifier = pkcs1_15.new(pub_key)
            verifier.verify(document_hash, b64decode(sign_tag.text))

            return True
        except Exception as e:
            # Handle verification failure or other exceptions
            print(f"Verification failed: {e}")
            return False
        finally:
            self.xml_data.append(sign_tag)

    def save(self):
        xml_tree = ElementTree(self.xml_data)
        xml_tree.write("License.lic")

    def save(self, file):
        xml_tree = ElementTree(self.xml_data)
        xml_tree.write(file)


if __name__ == '__main__':
    # 生成 RSA 密钥对
    key = RSA.generate(2048)
    public_key = key.publickey().export_key()
    print(public_key)
    private_key = key.export_key()
    print(private_key)

    license = (
        License.new()
        .with_unique_identifier("License123")
        .as_("Standard")
        .with_maximum_utilization(10)
        .with_product_features({"Sales Module": "yes",
                                "Workflow Module": "yes",
                                "Maximum Transactions": "10000",
                                "Mac Address": "b4:45:06:96:06:9b"})
        .licensed_to("John Doe", "john@example.com")
        # .expires_at(datetime(2025, 1, 31))
        .expires_at(datetime.now() + timedelta(365))
        .create_and_sign_with_private_key(private_key=private_key, pass_phrase="1234")
    )

    license.save("License.xml")

    # public_key = """MIIBKjCB4wYHKoZIzj0CATCB1wIBATAsBgcqhkjOPQEBAiEA/////wAAAAEAAAAAAAAAAAAAAAD///////////////8wWwQg/////wAAAAEAAAAAAAAAAAAAAAD///////////////wEIFrGNdiqOpPns+u9VXaYhrxlHQawzFOw9jvOPD4n0mBLAxUAxJ02CIbnBJNqZnjhE50mt4GffpAEIQNrF9Hy4SxCR/i85uVjpEDydwN9gS3rM6D0oTlF2JjClgIhAP////8AAAAA//////////+85vqtpxeehPO5ysL8YyVRAgEBA0IABNVLQ1xKY80BFMgGXec++Vw7n8vvNrq32PaHuBiYMm0PEj2JoB7qSSWhfgcjxNVJsxqJ6gDQVWgl0r7LH4dr0KU="""
    # license_data = """<License>
    #                               <Id>77d4c193-6088-4c64-9663-ed7398ae8c1a</Id>
    #                               <Type>Trial</Type>
    #                               <Expiration>Thu, 31 Dec 2009 23:00:00 GMT</Expiration>
    #                               <Quantity>1</Quantity>
    #                               <Customer>
    #                                 <Name>John Doe</Name>
    #                                 <Email>john@doe.tld</Email>
    #                               </Customer>
    #                               <LicenseAttributes>
    #                                 <Attribute name="Assembly Signature">123456789</Attribute>
    #                               </LicenseAttributes>
    #                               <ProductFeatures>
    #                                 <Feature name="Sales Module">yes</Feature>
    #                                 <Feature name="Workflow Module">yes</Feature>
    #                                 <Feature name="Maximum Transactions">10000</Feature>
    #                               </ProductFeatures>
    #                               <Signature>MEUCIQCa6A7Cts5ex4rGHAPxiXpy+2ocZzTDSP7SsddopKUx5QIgHnqv0DjoOpc+K9wALqajxxvmLCRJAywCX5vDAjmWqr8=</Signature>
    #                             </License>"""
    #
    # license = License.load_from_xml_string(license_data)
    print(license.product_features.get_all())

    validation_results = (
        License.load_from_file("License.xml")
        .validate()
        .assert_that(lambda lic: lic.product_features.contains("Sales Module"),
                     GeneralValidationFailure("Sales Module not licensed!"))
        .and_()
        .assert_that(lambda lic: lic.product_features.get("Mac Address") == "b4:45:06:96:06:9b",
                     GeneralValidationFailure("Target computer is not match"))
        .signature(public_key)
        .assert_valid_license()
    )

    # once you iterate over a generator, it gets consumed, and you cannot iterate over it again.
    # print(f"validation result size:{sum(1 for _ in validation_results)}")
    # # print(validation_results)
    # for validation_result in validation_results:
    #     print(validation_result)

    validation_results_list = list(validation_results)
    print(f"Validation result size: {len(validation_results_list)}")

    for validation_result in validation_results_list:
        print(validation_result)
